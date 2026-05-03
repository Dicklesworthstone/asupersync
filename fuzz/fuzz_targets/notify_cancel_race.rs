#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::thread;
use std::time::Duration;

use asupersync::sync::Notify;

#[derive(Debug, Clone)]
struct NotifyCancelTracker {
    operations: Arc<Mutex<Vec<String>>>,
    delivery_events: Arc<Mutex<Vec<DeliveryEvent>>>,
    invariant_violations: Arc<Mutex<Vec<InvariantViolation>>>,
}

#[derive(Debug, Clone)]
struct DeliveryEvent {
    waiter_id: usize,
    event_type: DeliveryType,
    operation_id: usize,
    timestamp: std::time::Instant,
}

#[derive(Debug, Clone, PartialEq)]
enum DeliveryType {
    NotifyReceived,
    WaiterCancelled,
    BatonPassed,
    StoredNotification,
}

#[derive(Debug, Clone)]
struct InvariantViolation {
    violation_type: String,
    description: String,
    operation_id: usize,
}

impl NotifyCancelTracker {
    fn new() -> Self {
        Self {
            operations: Arc::new(Mutex::new(Vec::new())),
            delivery_events: Arc::new(Mutex::new(Vec::new())),
            invariant_violations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_operation(&self, op: &str) {
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(op.to_string());
        }
    }

    fn record_delivery_event(&self, event: DeliveryEvent) {
        if let Ok(mut events) = self.delivery_events.lock() {
            events.push(event);
        }
    }

    fn record_violation(&self, violation: InvariantViolation) {
        if let Ok(mut violations) = self.invariant_violations.lock() {
            violations.push(violation);
        }
    }

    fn validate_atomic_delivery_invariants(&self) {
        if let Ok(events) = self.delivery_events.lock() {
            // Check for double-delivery: same notify operation delivered to multiple waiters
            let mut notify_deliveries = std::collections::HashMap::new();

            for event in events.iter() {
                if event.event_type == DeliveryType::NotifyReceived {
                    let count = notify_deliveries.entry(event.operation_id).or_insert(0);
                    *count += 1;

                    if *count > 1 {
                        self.record_violation(InvariantViolation {
                            violation_type: "double_delivery".to_string(),
                            description: format!(
                                "Operation {} delivered to {} waiters (double delivery)",
                                event.operation_id, count
                            ),
                            operation_id: event.operation_id,
                        });
                    }
                }
            }

            // Check for lost notifications: notify_one without any delivery or store
            let mut notify_operations = std::collections::HashSet::new();
            let mut delivered_operations = std::collections::HashSet::new();
            let mut stored_operations = std::collections::HashSet::new();

            for event in events.iter() {
                match event.event_type {
                    DeliveryType::NotifyReceived => {
                        delivered_operations.insert(event.operation_id);
                    }
                    DeliveryType::StoredNotification => {
                        stored_operations.insert(event.operation_id);
                    }
                    _ => {}
                }
            }

            // Add notify operations (we'll track these separately)
            if let Ok(ops) = self.operations.lock() {
                for (i, op) in ops.iter().enumerate() {
                    if op.starts_with("notify_one_") {
                        notify_operations.insert(i);
                    }
                }
            }

            for &op_id in &notify_operations {
                if !delivered_operations.contains(&op_id) && !stored_operations.contains(&op_id) {
                    self.record_violation(InvariantViolation {
                        violation_type: "lost_notification".to_string(),
                        description: format!(
                            "Operation {} was neither delivered nor stored (lost notification)",
                            op_id
                        ),
                        operation_id: op_id,
                    });
                }
            }
        }

        // Check for any violations and panic if found
        if let Ok(violations) = self.invariant_violations.lock() {
            if !violations.is_empty() {
                for violation in violations.iter() {
                    self.record_operation(&format!(
                        "VIOLATION: {} - {}",
                        violation.violation_type, violation.description
                    ));
                }
                panic!(
                    "Notify cancel race invariant violations detected: {} violations",
                    violations.len()
                );
            }
        }
    }
}

struct TrackedWaker {
    waiter_id: usize,
    tracker: NotifyCancelTracker,
    operation_id: usize,
    waked: Arc<Mutex<bool>>,
}

impl TrackedWaker {
    fn new(waiter_id: usize, operation_id: usize, tracker: NotifyCancelTracker) -> Self {
        Self {
            waiter_id,
            operation_id,
            tracker,
            waked: Arc::new(Mutex::new(false)),
        }
    }

    fn was_waked(&self) -> bool {
        if let Ok(waked) = self.waked.lock() {
            *waked
        } else {
            false
        }
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
            waiter_id: self.waiter_id,
            operation_id: self.operation_id,
            tracker: self.tracker.clone(),
            waked: Arc::clone(&self.waked),
        }
    }
}

// RawWaker vtable for TrackedWaker
static TRACKED_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    tracked_waker_clone,
    tracked_waker_wake,
    tracked_waker_wake_by_ref,
    tracked_waker_drop,
);

unsafe fn tracked_waker_clone(data: *const ()) -> RawWaker {
    let arc = Arc::from_raw(data as *const TrackedWaker);
    let cloned = arc.clone();
    std::mem::forget(arc);
    let new_data = Arc::into_raw(cloned) as *const ();
    RawWaker::new(new_data, &TRACKED_WAKER_VTABLE)
}

unsafe fn tracked_waker_wake(data: *const ()) {
    let arc = Arc::from_raw(data as *const TrackedWaker);
    if let Ok(mut waked) = arc.waked.lock() {
        *waked = true;
    }
    arc.tracker.record_delivery_event(DeliveryEvent {
        waiter_id: arc.waiter_id,
        event_type: DeliveryType::NotifyReceived,
        operation_id: arc.operation_id,
        timestamp: std::time::Instant::now(),
    });
}

unsafe fn tracked_waker_wake_by_ref(data: *const ()) {
    let arc = Arc::from_raw(data as *const TrackedWaker);
    if let Ok(mut waked) = arc.waked.lock() {
        *waked = true;
    }
    arc.tracker.record_delivery_event(DeliveryEvent {
        waiter_id: arc.waiter_id,
        event_type: DeliveryType::NotifyReceived,
        operation_id: arc.operation_id,
        timestamp: std::time::Instant::now(),
    });
    std::mem::forget(arc);
}

unsafe fn tracked_waker_drop(data: *const ()) {
    let _arc = Arc::from_raw(data as *const TrackedWaker);
}

#[derive(Debug, Clone, Arbitrary)]
struct NotifyCancelConfig {
    waiter_count: u8,
    pattern: CancelPattern,
}

#[derive(Debug, Clone, Arbitrary)]
enum CancelPattern {
    SimpleNotifyOneCancel,
    NotifyOneWithBatonPass { cancel_delay_us: u16 },
    BroadcastThenCancel { cancel_waiters: Vec<u8> },
    ConcurrentNotifyCancel { operations: Vec<Operation> },
    BatonPassChain { chain_length: u8 },
    StoredNotificationCancel { store_first: bool },
}

#[derive(Debug, Clone, Arbitrary)]
enum Operation {
    NotifyOne { delay_us: u16 },
    NotifyWaiters { delay_us: u16 },
    CancelWaiter { waiter_id: u8, delay_us: u16 },
    RegisterWaiter { waiter_id: u8 },
    CheckStoredCount,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let config: NotifyCancelConfig = u.arbitrary().unwrap_or(NotifyCancelConfig {
        waiter_count: 3,
        pattern: CancelPattern::SimpleNotifyOneCancel,
    });

    // Limit the number of waiters to prevent excessive test time
    if config.waiter_count == 0 || config.waiter_count > 8 {
        return;
    }

    let tracker = NotifyCancelTracker::new();
    let notify = Arc::new(Notify::new());

    // Execute the pattern
    match config.pattern {
        CancelPattern::SimpleNotifyOneCancel => {
            test_simple_notify_one_cancel(&tracker, &notify, config.waiter_count);
        }

        CancelPattern::NotifyOneWithBatonPass { cancel_delay_us } => {
            test_notify_one_with_baton_pass(
                &tracker,
                &notify,
                config.waiter_count,
                cancel_delay_us,
            );
        }

        CancelPattern::BroadcastThenCancel { cancel_waiters } => {
            test_broadcast_then_cancel(&tracker, &notify, config.waiter_count, &cancel_waiters);
        }

        CancelPattern::ConcurrentNotifyCancel { operations } => {
            test_concurrent_notify_cancel(&tracker, &notify, config.waiter_count, operations);
        }

        CancelPattern::BatonPassChain { chain_length } => {
            test_baton_pass_chain(&tracker, &notify, config.waiter_count, chain_length.min(6));
        }

        CancelPattern::StoredNotificationCancel { store_first } => {
            test_stored_notification_cancel(&tracker, &notify, config.waiter_count, store_first);
        }
    }

    // Validate all invariants
    tracker.validate_atomic_delivery_invariants();
});

fn test_simple_notify_one_cancel(tracker: &NotifyCancelTracker, notify: &Notify, waiter_count: u8) {
    tracker.record_operation("test_simple_notify_one_cancel");

    let mut waiters = Vec::new();
    let mut wakers = Vec::new();

    // Create waiters and register them
    for i in 0..waiter_count {
        let mut waiter = notify.notified();
        let tracked_waker = TrackedWaker::new(i as usize, 1, tracker.clone());
        let waker = tracked_waker.create_waker();
        let mut context = Context::from_waker(&waker);

        let _ = Pin::new(&mut waiter).poll(&mut context);
        waiters.push(waiter);
        wakers.push(tracked_waker);
    }

    // Notify one waiter
    tracker.record_operation("notify_one_1");
    notify.notify_one();

    // Cancel the first waiter (might trigger baton-passing)
    tracker.record_delivery_event(DeliveryEvent {
        waiter_id: 0,
        event_type: DeliveryType::WaiterCancelled,
        operation_id: 1,
        timestamp: std::time::Instant::now(),
    });
    drop(waiters.remove(0));

    // Check remaining waiters
    for (i, waiter) in waiters.iter_mut().enumerate() {
        let waker = wakers[i + 1].create_waker();
        let mut context = Context::from_waker(&waker);

        if let Poll::Ready(()) = Pin::new(waiter).poll(&mut context) {
            tracker.record_delivery_event(DeliveryEvent {
                waiter_id: i + 1,
                event_type: DeliveryType::BatonPassed,
                operation_id: 1,
                timestamp: std::time::Instant::now(),
            });
        }
    }
}

fn test_notify_one_with_baton_pass(
    tracker: &NotifyCancelTracker,
    notify: &Notify,
    waiter_count: u8,
    cancel_delay_us: u16,
) {
    tracker.record_operation("test_notify_one_with_baton_pass");

    let mut waiters = Vec::new();
    let mut wakers = Vec::new();

    // Create and register waiters
    for i in 0..waiter_count {
        let mut waiter = notify.notified();
        let tracked_waker = TrackedWaker::new(i as usize, 2, tracker.clone());
        let waker = tracked_waker.create_waker();
        let mut context = Context::from_waker(&waker);

        let _ = Pin::new(&mut waiter).poll(&mut context);
        waiters.push(waiter);
        wakers.push(tracked_waker);
    }

    // Notify one
    tracker.record_operation("notify_one_2");
    notify.notify_one();

    // Delay before cancelling
    if cancel_delay_us > 0 {
        thread::sleep(Duration::from_micros(cancel_delay_us.min(1000) as u64));
    }

    // Cancel the potentially-notified waiter
    if !waiters.is_empty() {
        tracker.record_delivery_event(DeliveryEvent {
            waiter_id: 0,
            event_type: DeliveryType::WaiterCancelled,
            operation_id: 2,
            timestamp: std::time::Instant::now(),
        });
        drop(waiters.remove(0));
        wakers.remove(0);
    }

    // Check if baton was passed to remaining waiters
    for (i, waiter) in waiters.iter_mut().enumerate() {
        let waker = wakers[i].create_waker();
        let mut context = Context::from_waker(&waker);

        if let Poll::Ready(()) = Pin::new(waiter).poll(&mut context) {
            tracker.record_delivery_event(DeliveryEvent {
                waiter_id: wakers[i].waiter_id,
                event_type: DeliveryType::BatonPassed,
                operation_id: 2,
                timestamp: std::time::Instant::now(),
            });
            break; // Only one should receive the baton
        }
    }
}

fn test_broadcast_then_cancel(
    tracker: &NotifyCancelTracker,
    notify: &Notify,
    waiter_count: u8,
    cancel_waiters: &[u8],
) {
    tracker.record_operation("test_broadcast_then_cancel");

    let mut waiters = Vec::new();
    let mut wakers = Vec::new();

    // Create and register waiters
    for i in 0..waiter_count {
        let mut waiter = notify.notified();
        let tracked_waker = TrackedWaker::new(i as usize, 3, tracker.clone());
        let waker = tracked_waker.create_waker();
        let mut context = Context::from_waker(&waker);

        let _ = Pin::new(&mut waiter).poll(&mut context);
        waiters.push(waiter);
        wakers.push(tracked_waker);
    }

    // Broadcast to all waiters
    tracker.record_operation("notify_waiters_3");
    notify.notify_waiters();

    // Cancel specified waiters
    let mut cancelled_indices = Vec::new();
    for &waiter_idx in cancel_waiters.iter().take(waiter_count as usize) {
        let idx = (waiter_idx as usize) % waiters.len();
        if !cancelled_indices.contains(&idx) {
            tracker.record_delivery_event(DeliveryEvent {
                waiter_id: idx,
                event_type: DeliveryType::WaiterCancelled,
                operation_id: 3,
                timestamp: std::time::Instant::now(),
            });
            cancelled_indices.push(idx);
        }
    }

    // Remove cancelled waiters in reverse order to maintain indices
    cancelled_indices.sort_unstable();
    cancelled_indices.reverse();
    for idx in cancelled_indices {
        if idx < waiters.len() {
            waiters.remove(idx);
            wakers.remove(idx);
        }
    }

    // Check remaining waiters - they should all be ready from broadcast
    for (i, waiter) in waiters.iter_mut().enumerate() {
        let waker = wakers[i].create_waker();
        let mut context = Context::from_waker(&waker);

        if let Poll::Ready(()) = Pin::new(waiter).poll(&mut context) {
            tracker.record_delivery_event(DeliveryEvent {
                waiter_id: wakers[i].waiter_id,
                event_type: DeliveryType::NotifyReceived,
                operation_id: 3,
                timestamp: std::time::Instant::now(),
            });
        }
    }
}

fn test_concurrent_notify_cancel(
    tracker: &NotifyCancelTracker,
    notify: &Notify,
    waiter_count: u8,
    operations: Vec<Operation>,
) {
    tracker.record_operation("test_concurrent_notify_cancel");

    let mut waiters = Vec::new();
    let mut wakers = Vec::new();
    let mut operation_counter = 4;

    // Create initial waiters
    for i in 0..waiter_count.min(5) {
        let mut waiter = notify.notified();
        let tracked_waker = TrackedWaker::new(i as usize, operation_counter, tracker.clone());
        let waker = tracked_waker.create_waker();
        let mut context = Context::from_waker(&waker);

        let _ = Pin::new(&mut waiter).poll(&mut context);
        waiters.push(waiter);
        wakers.push(tracked_waker);
    }

    // Execute operations
    for operation in operations.iter().take(15) {
        operation_counter += 1;
        match operation {
            Operation::NotifyOne { delay_us } => {
                if *delay_us > 0 {
                    thread::sleep(Duration::from_micros((*delay_us).min(500) as u64));
                }
                tracker.record_operation(&format!("notify_one_{}", operation_counter));
                notify.notify_one();
            }

            Operation::NotifyWaiters { delay_us } => {
                if *delay_us > 0 {
                    thread::sleep(Duration::from_micros((*delay_us).min(500) as u64));
                }
                tracker.record_operation(&format!("notify_waiters_{}", operation_counter));
                notify.notify_waiters();
            }

            Operation::CancelWaiter {
                waiter_id,
                delay_us,
            } => {
                if *delay_us > 0 {
                    thread::sleep(Duration::from_micros((*delay_us).min(500) as u64));
                }
                let idx = (*waiter_id as usize) % waiters.len().max(1);
                if idx < waiters.len() {
                    tracker.record_delivery_event(DeliveryEvent {
                        waiter_id: idx,
                        event_type: DeliveryType::WaiterCancelled,
                        operation_id: operation_counter,
                        timestamp: std::time::Instant::now(),
                    });
                    waiters.remove(idx);
                    wakers.remove(idx);
                }
            }

            Operation::RegisterWaiter { waiter_id } => {
                let waiter_idx = *waiter_id as usize;
                if waiters.len() < 8 {
                    let mut waiter = notify.notified();
                    let tracked_waker =
                        TrackedWaker::new(waiter_idx, operation_counter, tracker.clone());
                    let waker = tracked_waker.create_waker();
                    let mut context = Context::from_waker(&waker);

                    let _ = Pin::new(&mut waiter).poll(&mut context);
                    waiters.push(waiter);
                    wakers.push(tracked_waker);
                }
            }

            Operation::CheckStoredCount => {
                let stored = notify
                    .stored_notifications
                    .load(std::sync::atomic::Ordering::Acquire);
                tracker.record_operation(&format!("stored_count_{}", stored));
            }
        }
    }

    // Final poll of remaining waiters
    for (i, waiter) in waiters.iter_mut().enumerate() {
        let waker = wakers[i].create_waker();
        let mut context = Context::from_waker(&waker);

        if let Poll::Ready(()) = Pin::new(waiter).poll(&mut context) {
            tracker.record_delivery_event(DeliveryEvent {
                waiter_id: wakers[i].waiter_id,
                event_type: DeliveryType::NotifyReceived,
                operation_id: wakers[i].operation_id,
                timestamp: std::time::Instant::now(),
            });
        }
    }
}

fn test_baton_pass_chain(
    tracker: &NotifyCancelTracker,
    notify: &Notify,
    waiter_count: u8,
    chain_length: u8,
) {
    tracker.record_operation("test_baton_pass_chain");

    let mut waiters = Vec::new();
    let mut wakers = Vec::new();

    // Create waiters
    for i in 0..waiter_count {
        let mut waiter = notify.notified();
        let tracked_waker = TrackedWaker::new(i as usize, 5, tracker.clone());
        let waker = tracked_waker.create_waker();
        let mut context = Context::from_waker(&waker);

        let _ = Pin::new(&mut waiter).poll(&mut context);
        waiters.push(waiter);
        wakers.push(tracked_waker);
    }

    // Send one notification
    tracker.record_operation("notify_one_5");
    notify.notify_one();

    // Cancel waiters in chain to test baton passing
    let cancel_count = chain_length.min(waiter_count.saturating_sub(1));
    for i in 0..cancel_count {
        if !waiters.is_empty() {
            tracker.record_delivery_event(DeliveryEvent {
                waiter_id: i as usize,
                event_type: DeliveryType::WaiterCancelled,
                operation_id: 5,
                timestamp: std::time::Instant::now(),
            });
            waiters.remove(0);
            wakers.remove(0);
        }
    }

    // Check if final waiter got the baton
    if let Some(waiter) = waiters.first_mut() {
        if let Some(tracked_waker) = wakers.first() {
            let waker = tracked_waker.create_waker();
            let mut context = Context::from_waker(&waker);

            if let Poll::Ready(()) = Pin::new(waiter).poll(&mut context) {
                tracker.record_delivery_event(DeliveryEvent {
                    waiter_id: tracked_waker.waiter_id,
                    event_type: DeliveryType::BatonPassed,
                    operation_id: 5,
                    timestamp: std::time::Instant::now(),
                });
            }
        }
    }
}

fn test_stored_notification_cancel(
    tracker: &NotifyCancelTracker,
    notify: &Notify,
    _waiter_count: u8,
    store_first: bool,
) {
    tracker.record_operation("test_stored_notification_cancel");

    if store_first {
        // Store notification first, then create waiter and cancel it
        tracker.record_operation("notify_one_6");
        notify.notify_one();

        tracker.record_delivery_event(DeliveryEvent {
            waiter_id: 999,
            event_type: DeliveryType::StoredNotification,
            operation_id: 6,
            timestamp: std::time::Instant::now(),
        });

        let mut waiter = notify.notified();
        let tracked_waker = TrackedWaker::new(0, 6, tracker.clone());
        let waker = tracked_waker.create_waker();
        let mut context = Context::from_waker(&waker);

        // Poll should be ready immediately due to stored notification
        if let Poll::Ready(()) = Pin::new(&mut waiter).poll(&mut context) {
            tracker.record_delivery_event(DeliveryEvent {
                waiter_id: 0,
                event_type: DeliveryType::NotifyReceived,
                operation_id: 6,
                timestamp: std::time::Instant::now(),
            });
        }

        // Cancel this waiter - stored notification should have been consumed
        drop(waiter);
        tracker.record_delivery_event(DeliveryEvent {
            waiter_id: 0,
            event_type: DeliveryType::WaiterCancelled,
            operation_id: 6,
            timestamp: std::time::Instant::now(),
        });
    } else {
        // Create waiter, then notify and cancel
        let mut waiter = notify.notified();
        let tracked_waker = TrackedWaker::new(0, 7, tracker.clone());
        let waker = tracked_waker.create_waker();
        let mut context = Context::from_waker(&waker);

        let _ = Pin::new(&mut waiter).poll(&mut context);

        tracker.record_operation("notify_one_7");
        notify.notify_one();

        // Cancel waiter - this should trigger storage of notification
        drop(waiter);
        tracker.record_delivery_event(DeliveryEvent {
            waiter_id: 0,
            event_type: DeliveryType::WaiterCancelled,
            operation_id: 7,
            timestamp: std::time::Instant::now(),
        });

        tracker.record_delivery_event(DeliveryEvent {
            waiter_id: 999,
            event_type: DeliveryType::StoredNotification,
            operation_id: 7,
            timestamp: std::time::Instant::now(),
        });
    }
}
