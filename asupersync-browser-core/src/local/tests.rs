use super::*;
use asupersync::types::{WasmAbiValue, WasmScopeEnterRequest};
use std::cell::Cell;
use std::future::{pending, poll_fn, ready};
use std::marker::PhantomPinned;
use std::sync::atomic::AtomicUsize;

fn ok(value: u64) -> WasmAbiOutcomeEnvelope {
    WasmAbiOutcomeEnvelope::Ok { value: WasmAbiValue::U64(value) }
}

struct Owners { runtime: WasmHandleRef, scope: WasmHandleRef }
impl Owners {
    fn new() -> Self {
        crate::reset_dispatcher_for_tests();
        configure_local_executor(LocalExecutorConfig::default()).unwrap();
        Self::additional()
    }
    fn additional() -> Self {
        let runtime = with_dispatcher(|d| d.runtime_create(None)).unwrap();
        let scope = with_dispatcher(|d| d.scope_enter(&WasmScopeEnterRequest {
            parent: runtime, label: Some("actual-local-futures".into()),
        }, None)).unwrap();
        Self { runtime, scope }
    }
    fn spawn<F: Future<Output = WasmAbiOutcomeEnvelope> + 'static>(&self, future: F) -> LocalTask {
        spawn_local_future(request(self.scope), future, None).unwrap()
    }
}
impl Drop for Owners {
    fn drop(&mut self) {
        if dispatcher_handle_is_live(&self.runtime) {
            crate::runtime_close_impl(serde_json::to_string(&self.runtime).unwrap(), None).unwrap();
        }
    }
}
fn request(scope: WasmHandleRef) -> WasmTaskSpawnRequest {
    WasmTaskSpawnRequest { scope, label: None, cancel_kind: None }
}
fn drive() -> Poll<()> { poll_local_tasks(&mut Context::from_waker(Waker::noop())) }
fn joined(task: &mut LocalTask) -> LocalTaskCompletion {
    match Pin::new(task).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("task did not actually complete"),
    }
}
fn live_handles() -> usize {
    crate::DISPATCHER.with(|d| d.borrow().handles().memory_report().live_handles)
}

struct Never { polls: Rc<Cell<usize>>, drops: Rc<Cell<usize>> }
impl Future for Never {
    type Output = WasmAbiOutcomeEnvelope;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.polls.set(self.polls.get() + 1);
        Poll::Pending
    }
}
impl Drop for Never { fn drop(&mut self) { self.drops.set(self.drops.get() + 1); } }
fn never() -> (Never, Rc<Cell<usize>>, Rc<Cell<usize>>) {
    let polls = Rc::new(Cell::new(0));
    let drops = Rc::new(Cell::new(0));
    (Never { polls: Rc::clone(&polls), drops: Rc::clone(&drops) }, polls, drops)
}

#[test]
fn lazy_actual_execution_returns_the_real_value_and_releases_the_handle() {
    let owners = Owners::new();
    let polls = Rc::new(Cell::new(0));
    let observed = Rc::clone(&polls);
    let mut task = owners.spawn(poll_fn(move |_| {
        observed.set(observed.get() + 1);
        Poll::Ready(ok(42))
    }));
    assert_eq!(polls.get(), 0);
    assert_eq!(active_local_tasks(), 1);
    assert!(drive().is_ready());
    assert_eq!(polls.get(), 1);
    assert_eq!(joined(&mut task), LocalTaskCompletion { outcome: ok(42), publication_error: None });
    assert!(!dispatcher_handle_is_live(&task.handle()));
    assert_eq!(active_local_tasks(), 0);
}

#[test]
fn real_non_send_non_unpin_future_is_polled_without_moving_its_state() {
    struct Pinned { value: Rc<Cell<u64>>, _pin: PhantomPinned }
    impl Future for Pinned {
        type Output = WasmAbiOutcomeEnvelope;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(ok(self.as_ref().get_ref().value.get()))
        }
    }
    let owners = Owners::new();
    let mut task = owners.spawn(Pinned { value: Rc::new(Cell::new(23)), _pin: PhantomPinned });
    assert!(drive().is_ready());
    assert_eq!(joined(&mut task).outcome, ok(23));
}

#[test]
fn pending_futures_are_not_busy_polled_and_external_wakes_resume_them() {
    let owners = Owners::new();
    let ready_flag = Rc::new(Cell::new(false));
    let flag = Rc::clone(&ready_flag);
    let slot = Rc::new(RefCell::new(None::<Waker>));
    let destination = Rc::clone(&slot);
    let polls = Rc::new(Cell::new(0));
    let count = Rc::clone(&polls);
    let mut task = owners.spawn(poll_fn(move |cx| {
        count.set(count.get() + 1);
        if flag.get() { Poll::Ready(ok(17)) }
        else { *destination.borrow_mut() = Some(cx.waker().clone()); Poll::Pending }
    }));
    assert!(drive().is_pending());
    for _ in 0..5 { assert!(drive().is_pending()); }
    assert_eq!(polls.get(), 1);
    ready_flag.set(true);
    let wake = slot.borrow_mut().take().unwrap();
    // Only the thread-safe wake token moves; the Rc-owning future stays local.
    std::thread::spawn(move || { wake.wake_by_ref(); wake.wake_by_ref(); }).join().unwrap();
    assert!(drive().is_ready());
    assert_eq!(polls.get(), 2);
    assert_eq!(joined(&mut task).outcome, ok(17));
}

#[test]
fn capacity_refusal_creates_no_dispatcher_handle_and_cancel_releases_capacity() {
    let owners = Owners::new();
    configure_local_executor(LocalExecutorConfig { max_tasks: 1, polls_per_turn: 1 }).unwrap();
    let (future, polls, drops) = never();
    let mut task = owners.spawn(future);
    let before = live_handles();
    assert!(spawn_local_future(request(owners.scope), ready(ok(99)), None).is_err());
    assert_eq!(live_handles(), before);
    assert_eq!(active_local_tasks(), 1);
    task.cancel("user", Some("stop before first poll".into())).unwrap();
    assert_eq!(polls.get(), 0);
    assert_eq!(drops.get(), 1);
    assert!(matches!(joined(&mut task).outcome, WasmAbiOutcomeEnvelope::Cancelled { .. }));
    assert_eq!(active_local_tasks(), 0);
    let mut replacement = owners.spawn(ready(ok(3)));
    assert!(drive().is_ready());
    assert_eq!(joined(&mut replacement).outcome, ok(3));
}

#[test]
fn finite_quantum_visits_ready_tasks_round_robin() {
    let owners = Owners::new();
    configure_local_executor(LocalExecutorConfig { max_tasks: 4, polls_per_turn: 2 }).unwrap();
    let order = Rc::new(RefCell::new(Vec::new()));
    let mut tasks = Vec::new();
    for label in 0..3_u64 {
        let order = Rc::clone(&order);
        let mut polls = 0;
        tasks.push(owners.spawn(poll_fn(move |cx| {
            order.borrow_mut().push(label);
            polls += 1;
            if polls == 2 { Poll::Ready(ok(label)) }
            else { cx.waker().wake_by_ref(); Poll::Pending }
        })));
    }
    assert!(drive().is_pending());
    assert_eq!(&*order.borrow(), &[0, 1]);
    assert!(drive().is_pending());
    assert_eq!(&*order.borrow(), &[0, 1, 2, 0]);
    assert!(drive().is_ready());
    assert_eq!(&*order.borrow(), &[0, 1, 2, 0, 1, 2]);
    for (index, task) in tasks.iter_mut().enumerate() {
        assert_eq!(joined(task).outcome, ok(index as u64));
    }
}

#[test]
fn forged_js_join_cannot_complete_or_release_a_rust_future() {
    let owners = Owners::new();
    let mut task = owners.spawn(ready(ok(8)));
    let before = live_handles();
    assert!(crate::task_join_impl(
        serde_json::to_string(&task.handle()).unwrap(),
        serde_json::to_string(&ok(999)).unwrap(), None,
    ).is_err());
    assert_eq!(live_handles(), before);
    assert!(drive().is_ready());
    assert_eq!(joined(&mut task).outcome, ok(8));
}

#[test]
fn raw_abi_cancel_retires_a_parked_future_and_preserves_attribution() {
    let owners = Owners::new();
    let (future, polls, drops) = never();
    let mut task = owners.spawn(future);
    assert!(drive().is_pending());
    crate::task_cancel_impl(serde_json::to_string(&WasmTaskCancelRequest {
        task: task.handle(), kind: "deadline".into(), message: Some("caller deadline".into()),
    }).unwrap(), None).unwrap();
    assert_eq!(polls.get(), 1);
    assert_eq!(drops.get(), 1);
    let completion = joined(&mut task);
    let WasmAbiOutcomeEnvelope::Cancelled { cancellation } = completion.outcome else {
        panic!("a cancel request must not become an invented success")
    };
    assert_eq!(cancellation.kind, "deadline");
    assert_eq!(cancellation.message.as_deref(), Some("caller deadline"));
    assert_eq!(cancellation.phase, "completed");
    assert!(completion.publication_error.is_none());
    assert!(drive().is_ready());
}

#[test]
fn cancellation_during_a_ready_poll_wins_without_dropping_the_in_flight_future_twice() {
    let owners = Owners::new();
    let slot = Rc::new(Cell::new(None));
    let selected = Rc::clone(&slot);
    let mut task = owners.spawn(poll_fn(move |_| {
        crate::task_cancel_impl(serde_json::to_string(&WasmTaskCancelRequest {
            task: selected.get().unwrap(), kind: "inside_poll".into(), message: None,
        }).unwrap(), None).unwrap();
        Poll::Ready(ok(99))
    }));
    slot.set(Some(task.handle()));
    assert!(drive().is_ready());
    assert!(matches!(joined(&mut task).outcome, WasmAbiOutcomeEnvelope::Cancelled { .. }));
}

#[test]
fn scope_close_drops_descendants_but_not_an_unrelated_runtime() {
    let owners = Owners::new();
    let other = Owners::additional();
    let nested = with_dispatcher(|d| d.scope_enter(&WasmScopeEnterRequest {
        parent: owners.scope, label: None,
    }, None)).unwrap();
    let (a, _, a_drops) = never();
    let (b, _, b_drops) = never();
    let (c, _, c_drops) = never();
    let mut a = owners.spawn(a);
    let mut b = spawn_local_future(request(nested), b, None).unwrap();
    let c = other.spawn(c);
    assert!(drive().is_pending());
    crate::scope_close_impl(serde_json::to_string(&owners.scope).unwrap(), None).unwrap();
    assert_eq!(a_drops.get(), 1);
    assert_eq!(b_drops.get(), 1);
    assert_eq!(c_drops.get(), 0);
    assert_eq!(active_local_tasks(), 1);
    assert!(matches!(joined(&mut a).outcome, WasmAbiOutcomeEnvelope::Cancelled { .. }));
    assert!(matches!(joined(&mut b).outcome, WasmAbiOutcomeEnvelope::Cancelled { .. }));
    c.cancel("done", None).unwrap();
    assert_eq!(c_drops.get(), 1);
}

#[test]
fn closing_ownership_from_inside_a_poll_is_rejected_instead_of_claiming_quiescence() {
    let owners = Owners::new();
    let scope = owners.scope;
    let mut task = owners.spawn(poll_fn(move |_| {
        assert!(crate::scope_close_impl(serde_json::to_string(&scope).unwrap(), None).is_err());
        assert!(dispatcher_handle_is_live(&scope));
        Poll::Ready(ok(2))
    }));
    assert!(drive().is_ready());
    assert_eq!(joined(&mut task).outcome, ok(2));
}

#[derive(Default)]
struct CountWake(AtomicUsize);
impl Wake for CountWake {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::Relaxed); }
}

#[test]
fn join_waker_replacement_notifies_only_the_current_observer() {
    let owners = Owners::new();
    let mut task = owners.spawn(ready(ok(1)));
    let first = Arc::new(CountWake::default());
    let second = Arc::new(CountWake::default());
    for count in [&first, &second] {
        let waker = Waker::from(Arc::clone(count));
        assert!(Pin::new(&mut task).poll(&mut Context::from_waker(&waker)).is_pending());
    }
    assert!(drive().is_ready());
    assert_eq!(first.0.load(Ordering::Relaxed), 0);
    assert_eq!(second.0.load(Ordering::Relaxed), 1);
    assert_eq!(joined(&mut task).outcome, ok(1));
}

#[test]
fn dropping_join_releases_its_waker_without_detaching_the_owned_future() {
    let owners = Owners::new();
    let (future, _, drops) = never();
    let mut task = owners.spawn(future);
    let counter = Arc::new(CountWake::default());
    let weak = Arc::downgrade(&counter);
    let waker = Waker::from(counter);
    assert!(Pin::new(&mut task).poll(&mut Context::from_waker(&waker)).is_pending());
    drop(waker);
    drop(task);
    assert!(weak.upgrade().is_none());
    assert_eq!(active_local_tasks(), 1);
    assert_eq!(drops.get(), 0);
    drop(owners);
    assert_eq!(drops.get(), 1);
    assert_eq!(active_local_tasks(), 0);
}

#[test]
fn poll_panic_is_a_real_terminal_outcome_and_siblings_still_execute() {
    let owners = Owners::new();
    let mut panicking = owners.spawn(poll_fn(|_| -> Poll<WasmAbiOutcomeEnvelope> { panic!("poll sentinel") }));
    let mut sibling = owners.spawn(ready(ok(5)));
    assert!(drive().is_ready());
    assert!(matches!(joined(&mut panicking).outcome,
        WasmAbiOutcomeEnvelope::Panicked { message } if message.contains("poll sentinel")));
    assert_eq!(joined(&mut sibling).outcome, ok(5));
    assert_eq!(active_local_tasks(), 0);
}

#[test]
fn cleanup_panic_overrides_a_ready_value_after_the_future_is_retired() {
    struct CleanupPanic;
    impl Future for CleanupPanic {
        type Output = WasmAbiOutcomeEnvelope;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> { Poll::Ready(ok(1)) }
    }
    impl Drop for CleanupPanic { fn drop(&mut self) { panic!("cleanup sentinel"); } }
    let owners = Owners::new();
    let mut task = owners.spawn(CleanupPanic);
    assert!(drive().is_ready());
    assert!(matches!(joined(&mut task).outcome,
        WasmAbiOutcomeEnvelope::Panicked { message } if message.contains("cleanup sentinel")));
    assert_eq!(active_local_tasks(), 0);
}

#[test]
fn live_executor_reconfiguration_and_dispatcher_reset_fail_closed() {
    let owners = Owners::new();
    assert!(configure_local_executor(LocalExecutorConfig { max_tasks: 0, polls_per_turn: 1 }).is_err());
    let mut task = owners.spawn(pending());
    assert!(configure_local_executor(LocalExecutorConfig::default()).is_err());
    assert!(catch_unwind(AssertUnwindSafe(crate::reset_dispatcher_for_tests)).is_err());
    assert!(dispatcher_handle_is_live(&task.handle()));
    task.cancel("cleanup", None).unwrap();
    assert!(matches!(joined(&mut task).outcome, WasmAbiOutcomeEnvelope::Cancelled { .. }));
}

#[test]
fn websocket_cancel_cannot_release_a_rust_task_through_the_wrong_adapter() {
    let owners = Owners::new();
    let mut task = owners.spawn(ready(ok(71)));
    let before = live_handles();
    let request = serde_json::json!({
        "socket": task.handle(), "kind": "forged_websocket_cancel", "message": null,
    });
    assert!(crate::websocket_cancel_impl(request.to_string(), None).is_err());
    assert_eq!(live_handles(), before);
    assert!(drive().is_ready());
    assert_eq!(joined(&mut task).outcome, ok(71));
}

#[test]
fn work_admitted_by_a_join_wake_is_not_mistaken_for_an_idle_executor() {
    struct SpawnOnWake {
        scope: WasmHandleRef,
        once: AtomicBool,
        ran: Arc<AtomicUsize>,
    }
    impl Wake for SpawnOnWake {
        fn wake(self: Arc<Self>) { self.wake_by_ref(); }
        fn wake_by_ref(self: &Arc<Self>) {
            if !self.once.swap(true, Ordering::Relaxed) {
                let ran = Arc::clone(&self.ran);
                let task = spawn_local_future(request(self.scope), async move {
                    ran.fetch_add(1, Ordering::Relaxed);
                    ok(2)
                }, None).unwrap();
                drop(task); // Still scope-owned; lack of a joiner cannot detach it.
            }
        }
    }
    let owners = Owners::new();
    configure_local_executor(LocalExecutorConfig { max_tasks: 2, polls_per_turn: 1 }).unwrap();
    let mut first = owners.spawn(ready(ok(1)));
    let ran = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(SpawnOnWake {
        scope: owners.scope, once: AtomicBool::new(false), ran: Arc::clone(&ran),
    }));
    assert!(Pin::new(&mut first).poll(&mut Context::from_waker(&waker)).is_pending());
    assert!(drive().is_pending());
    assert_eq!(ran.load(Ordering::Relaxed), 0);
    assert_eq!(active_local_tasks(), 1);
    assert!(drive().is_ready());
    assert_eq!(ran.load(Ordering::Relaxed), 1);
    assert_eq!(joined(&mut first).outcome, ok(1));
}

#[test]
fn retiring_future_keeps_its_capacity_and_rejects_forged_completion_during_drop() {
    struct Retiring {
        handle: Rc<Cell<Option<WasmHandleRef>>>,
        scope: WasmHandleRef,
        inspected: Rc<Cell<bool>>,
    }
    impl Future for Retiring {
        type Output = WasmAbiOutcomeEnvelope;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> { Poll::Ready(ok(6)) }
    }
    impl Drop for Retiring {
        fn drop(&mut self) {
            assert_eq!(active_local_tasks(), 1);
            assert!(spawn_local_future(request(self.scope), ready(ok(8)), None).is_err());
            assert!(crate::task_join_impl(
                serde_json::to_string(&self.handle.get().unwrap()).unwrap(),
                serde_json::to_string(&ok(99)).unwrap(), None,
            ).is_err());
            assert!(crate::scope_close_impl(serde_json::to_string(&self.scope).unwrap(), None).is_err());
            self.inspected.set(true);
        }
    }
    let owners = Owners::new();
    configure_local_executor(LocalExecutorConfig { max_tasks: 1, polls_per_turn: 1 }).unwrap();
    let handle = Rc::new(Cell::new(None));
    let inspected = Rc::new(Cell::new(false));
    let mut task = owners.spawn(Retiring {
        handle: Rc::clone(&handle), scope: owners.scope, inspected: Rc::clone(&inspected),
    });
    handle.set(Some(task.handle()));
    assert!(drive().is_ready());
    assert!(inspected.get());
    assert_eq!(joined(&mut task).outcome, ok(6));
    assert_eq!(active_local_tasks(), 0);
}

#[test]
fn stale_task_waker_cannot_wake_a_recycled_handle_generation() {
    let owners = Owners::new();
    let saved = Rc::new(RefCell::new(None));
    let slot = Rc::clone(&saved);
    let old = owners.spawn(poll_fn(move |cx| {
        *slot.borrow_mut() = Some(cx.waker().clone());
        Poll::Pending
    }));
    assert!(drive().is_pending());
    let old_handle = old.handle();
    old.cancel("replace", None).unwrap();
    let (future, polls, _) = never();
    let replacement = owners.spawn(future);
    assert_ne!(old_handle, replacement.handle());
    assert!(drive().is_pending());
    assert_eq!(polls.get(), 1);
    saved.borrow_mut().take().unwrap().wake();
    assert!(drive().is_pending());
    assert_eq!(polls.get(), 1);
    replacement.cancel("cleanup", None).unwrap();
}

#[test]
fn owner_close_retires_every_sibling_even_when_one_destructor_panics() {
    struct PanicOnDrop;
    impl Future for PanicOnDrop {
        type Output = WasmAbiOutcomeEnvelope;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> { Poll::Pending }
    }
    impl Drop for PanicOnDrop { fn drop(&mut self) { panic!("owner-close cleanup sentinel"); } }
    let owners = Owners::new();
    let mut bad = owners.spawn(PanicOnDrop);
    let (future, _, drops) = never();
    let mut sibling = owners.spawn(future);
    assert!(drive().is_pending());
    crate::scope_close_impl(serde_json::to_string(&owners.scope).unwrap(), None).unwrap();
    assert_eq!(drops.get(), 1);
    assert_eq!(active_local_tasks(), 0);
    assert!(matches!(joined(&mut bad).outcome, WasmAbiOutcomeEnvelope::Panicked { .. }));
    assert!(matches!(joined(&mut sibling).outcome, WasmAbiOutcomeEnvelope::Cancelled { .. }));
}

#[test]
fn rejected_owner_and_abi_version_do_not_allocate_task_handles() {
    let owners = Owners::new();
    let mut existing = owners.spawn(ready(ok(1)));
    let before = live_handles();
    assert!(spawn_local_future(request(existing.handle()), ready(ok(2)), None).is_err());
    assert!(spawn_local_future(request(owners.scope), ready(ok(3)), Some(WasmAbiVersion {
        major: u16::MAX, minor: 0,
    })).is_err());
    assert_eq!(active_local_tasks(), 1);
    assert_eq!(live_handles(), before);
    assert!(drive().is_ready());
    assert_eq!(joined(&mut existing).outcome, ok(1));
}

#[test]
fn driver_wake_panic_does_not_skip_a_cancelled_tasks_join_wake() {
    struct PanicWake;
    impl Wake for PanicWake {
        fn wake(self: Arc<Self>) { panic!("driver wake sentinel"); }
        fn wake_by_ref(self: &Arc<Self>) { panic!("driver wake sentinel"); }
    }
    let owners = Owners::new();
    let mut task = owners.spawn(pending());
    let counter = Arc::new(CountWake::default());
    let join_waker = Waker::from(Arc::clone(&counter));
    assert!(Pin::new(&mut task).poll(&mut Context::from_waker(&join_waker)).is_pending());
    let driver_waker = Waker::from(Arc::new(PanicWake));
    // No runnable task remains after the first poll, so no self-wake is needed.
    assert!(poll_local_tasks(&mut Context::from_waker(&driver_waker)).is_pending());
    assert!(catch_unwind(AssertUnwindSafe(|| task.cancel("stop", None))).is_err());
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    assert_eq!(active_local_tasks(), 0);
    assert!(matches!(joined(&mut task).outcome, WasmAbiOutcomeEnvelope::Cancelled { .. }));
    assert!(drive().is_ready());
}

#[test]
fn original_domain_error_and_returned_panic_are_not_relabelled_as_success() {
    let owners = Owners::new();
    let error = WasmAbiOutcomeEnvelope::Err {
        failure: asupersync::types::WasmAbiFailure {
            code: asupersync::types::WasmAbiErrorCode::InternalFailure,
            recoverability: asupersync::types::WasmAbiRecoverability::Transient,
            message: "original domain error".into(),
        },
    };
    let mut failure = owners.spawn(ready(error.clone()));
    let slot = Rc::new(Cell::new(None));
    let selected = Rc::clone(&slot);
    let mut panicked = owners.spawn(poll_fn(move |_| {
        crate::task_cancel_impl(serde_json::to_string(&WasmTaskCancelRequest {
            task: selected.get().unwrap(), kind: "during_poll".into(), message: None,
        }).unwrap(), None).unwrap();
        Poll::Ready(WasmAbiOutcomeEnvelope::Panicked { message: "returned panic".into() })
    }));
    slot.set(Some(panicked.handle()));
    assert!(drive().is_ready());
    assert_eq!(joined(&mut failure).outcome, error);
    assert_eq!(joined(&mut panicked).outcome,
        WasmAbiOutcomeEnvelope::Panicked { message: "returned panic".into() });
}
