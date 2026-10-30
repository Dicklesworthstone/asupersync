#![cfg(not(target_arch = "wasm32"))]

use super::*;
use crate::runtime::RuntimeBuilder;
use crate::supervision::BackoffStrategy;
use crate::{LabConfig, LabRuntime};
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

#[derive(Default)]
struct Latch { open: AtomicBool, parked: AtomicBool, wake: Notify, observed: Notify }
impl Latch {
    fn release(&self) { self.open.store(true, Ordering::Release); self.wake.notify_waiters(); }
    async fn wait(&self) {
        let mut wait = std::pin::pin!(self.wake.wait_until(|| self.open.load(Ordering::Acquire)));
        poll_fn(|task| {
            let result = wait.as_mut().poll(task);
            if result.is_pending() && !self.parked.swap(true, Ordering::AcqRel) {
                self.observed.notify_waiters();
            }
            result
        }).await
    }
    async fn wait_parked(&self) {
        self.observed.wait_until(|| self.parked.load(Ordering::Acquire)).await;
    }
}

#[derive(Default)]
struct Log {
    events: Mutex<Vec<(&'static str, u64, u64)>>,
    terminations: Mutex<Vec<(&'static str, u64, EventStopReason)>>,
    changed: Notify,
}
impl Log {
    async fn saw(&self, label: &'static str, event: u64) {
        self.changed.wait_until(|| self.events.lock().iter().any(|(l, _, e)| *l == label && *e == event)).await;
    }
}
#[derive(Clone)]
struct Plan {
    label: &'static str, log: Arc<Log>, starts: Arc<AtomicUsize>,
    fail: Option<u64>, panic: bool, hold: Option<(u64, Arc<Latch>)>,
    terminate: Option<Arc<Latch>>, terminate_error: bool, drop_panic: bool,
}
impl Plan {
    fn new(label: &'static str, log: &Arc<Log>) -> Self {
        Self { label, log: Arc::clone(log), starts: Arc::new(AtomicUsize::new(0)),
            fail: None, panic: false, hold: None, terminate: None, terminate_error: false, drop_panic: false }
    }
    fn factory(self) -> impl Fn(&Cx, ManagedGeneration) -> Handler + Send + Sync + 'static {
        move |_, generation| {
            self.starts.fetch_add(1, Ordering::AcqRel);
            Handler { plan: self.clone(), generation }
        }
    }
}
struct Handler { plan: Plan, generation: ManagedGeneration }
impl Drop for Handler {
    fn drop(&mut self) { assert!(!self.plan.drop_panic, "injected handler destructor panic"); }
}
impl EventHandler<u64> for Handler {
    type Error = &'static str;
    fn handle_event<'a>(&'a mut self, cx: &'a Cx, event: &'a u64) -> EventHandlerFuture<'a, Self::Error> {
        Box::pin(async move {
            if let Some((held, latch)) = &self.plan.hold {
                if event == held && wait_cancel(cx, latch.wait()).await.is_err() {
                    return Outcome::Cancelled(cancel_reason(cx));
                }
            }
            if self.generation.number == 1 && self.plan.fail == Some(*event) {
                assert!(!self.plan.panic, "injected event callback panic");
                return Outcome::Err("injected event failure");
            }
            self.plan.log.events.lock().push((self.plan.label, self.generation.number, *event));
            self.plan.log.changed.notify_waiters();
            Outcome::Ok(())
        })
    }
    fn terminate<'a>(&'a mut self, cx: &'a Cx, reason: EventStopReason)
        -> EventHandlerFuture<'a, Self::Error> {
        assert!(cx.checkpoint().is_ok(), "termination construction must be masked");
        Box::pin(async move {
            self.plan.log.terminations.lock().push((self.plan.label, self.generation.number, reason));
            self.plan.log.changed.notify_waiters();
            if let Some(latch) = &self.plan.terminate { latch.wait().await; }
            if self.plan.terminate_error { Outcome::Err("injected termination failure") }
            else { Outcome::Ok(()) }
        })
    }
}
fn policy() -> EventHandlerConfig {
    EventHandlerConfig::new(SupervisionConfig::new(4, Duration::from_secs(60))
        .with_backoff(BackoffStrategy::None))
}
fn native<F, Fut>(workers: usize, scenario: F)
where F: FnOnce(Cx) -> Fut + Send + 'static, Fut: Future<Output = ()> + Send + 'static,
{
    let (done_tx, done_rx) = std_mpsc::sync_channel(1);
    let runner = std::thread::spawn(move || {
        let builder = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers) };
        let runtime = builder.build().unwrap();
        let completed = Arc::new(AtomicBool::new(false));
        let completion = Arc::clone(&completed);
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            crate::time::timeout(cx.now(), Duration::from_secs(10), scenario(cx)).await
                .expect("event-manager scenario watchdog");
            completion.store(true, Ordering::Release);
        }));
        assert!(completed.load(Ordering::Acquire));
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        done_tx.send(()).unwrap();
    });
    match done_rx.recv_timeout(Duration::from_secs(20)) {
        Ok(()) | Err(std_mpsc::RecvTimeoutError::Disconnected) => runner.join().expect("native event-manager scenario"),
        Err(std_mpsc::RecvTimeoutError::Timeout) => panic!("native event-manager runner exceeded watchdog"),
    }
}

#[test]
fn native_handlers_run_independently_and_remove_observes_real_drain() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let log = Arc::new(Log::default());
            let hold = Arc::new(Latch::default());
            let mut a = Plan::new("a", &log);
            a.hold = Some((1, Arc::clone(&hold)));
            let b = Plan::new("b", &log);
            let mut manager = EventManager::open(&cx, EventManagerConfig::new(2, 2, 4)).await.unwrap();
            let a = manager.add_handler(&cx, "a", policy(), a.factory()).await.unwrap();
            let b = manager.add_handler(&cx, "b", policy(), b.factory()).await.unwrap();
            let a_generation = a.ready(&cx).await.unwrap();
            let b_generation = b.ready(&cx).await.unwrap();
            let mut impostor = a.clone();
            impostor.state = Arc::clone(&b.state);
            assert!(matches!(manager.remove_handler(&cx, &impostor).await, Err(EventManagerError::StaleHandler)));
            assert_ne!(a_generation.task, b_generation.task);
            assert_ne!(a_generation.region, b_generation.region);
            let emitter = manager.emitter();
            let receipt = emitter.notify(&cx, 1, EventBackpressure::Wait).await.unwrap();
            hold.wait_parked().await;
            log.saw("b", 1).await;
            assert!(!receipt.is_complete(), "fast handler must finish while its sibling is parked");
            let scope = cx.scope_with_budget(cx.budget_for_timeout(Duration::from_millis(10)));
            let waiting = receipt.clone();
            let mut waiter = cx.spawn_in(&scope, move |cx| async move { waiting.wait(&cx).await }).unwrap();
            let Err(EventManagerError::Interrupted { reason, report: partial, receipt: resumed }) =
                waiter.join(&cx).await.unwrap() else { panic!("budget must interrupt the processing wait"); };
            assert_eq!(reason.kind, crate::types::CancelKind::Deadline);
            assert_eq!(partial.recipients[0].status, EventStatus::Pending);
            assert_eq!(partial.recipients[1].status, EventStatus::Handled);
            hold.release();
            let report = resumed.wait(&cx).await.unwrap();
            assert_eq!(report.recipients.len(), 2);
            assert!(report.all_handled());
            let retired = manager.remove_handler(&cx, &a).await.unwrap();
            let completed = retired.supervisor.unwrap();
            assert_eq!(completed.started, 1);
            assert_eq!(completed.joined, 1);
            assert!(retired.close.is_ok());
            assert!(a.is_closed());
            let report = emitter.sync_notify(&cx, 2, EventBackpressure::Wait).await.unwrap();
            assert!(report.all_handled());
            assert_eq!(report.recipients.len(), 1);
            assert_eq!(report.recipients[0].handler.id(), b.id());
            assert_eq!(emitter.in_flight(), 0);
            assert!(manager.shutdown().await.close.is_ok());
        });
    }
}

#[test]
fn native_cancelled_fanout_rolls_back_all_reserved_mailboxes() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let log = Arc::new(Log::default());
            let hold = Arc::new(Latch::default());
            let a = Plan::new("a", &log);
            let mut b = Plan::new("b", &log);
            b.hold = Some((1, Arc::clone(&hold)));
            let mut manager = EventManager::open(&cx, EventManagerConfig::new(2, 1, 4)).await.unwrap();
            manager.add_handler(&cx, "a", policy(), a.factory()).await.unwrap().ready(&cx).await.unwrap();
            manager.add_handler(&cx, "b", policy(), b.factory()).await.unwrap().ready(&cx).await.unwrap();
            let emitter = manager.emitter();
            let first = emitter.notify(&cx, 1, EventBackpressure::Wait).await.unwrap();
            hold.wait_parked().await;
            let second = emitter.notify(&cx, 2, EventBackpressure::Wait).await.unwrap();
            log.saw("a", 2).await;
            assert!(matches!(emitter.notify(&cx, 3, EventBackpressure::Reject).await,
                Err(EventManagerError::Backpressured(_))));
            assert_eq!(emitter.in_flight(), 2);
            assert!(!log.events.lock().iter().any(|(_, _, event)| *event == 3));
            let parked = Arc::new(Latch::default());
            let observed = Arc::clone(&parked);
            let child_emitter = emitter.clone();
            let mut child = cx.spawn(move |cx| async move {
                let mut pending = std::pin::pin!(child_emitter.notify(&cx, 3, EventBackpressure::Wait));
                poll_fn(|task| {
                    let result = pending.as_mut().poll(task);
                    if result.is_pending() && !observed.parked.swap(true, Ordering::AcqRel) {
                        observed.observed.notify_waiters();
                    }
                    result
                }).await
            }).unwrap();
            parked.wait_parked().await;
            assert_eq!(emitter.in_flight(), 3);
            child = std::thread::spawn(move || { child.abort(); child }).join().unwrap();
            assert!(matches!(child.join(&cx).await.unwrap(), Err(EventManagerError::Cancelled(_))));
            assert_eq!(emitter.in_flight(), 2);
            assert!(!log.events.lock().iter().any(|(_, _, event)| *event == 3));
            hold.release();
            assert!(first.wait(&cx).await.unwrap().all_handled());
            assert!(second.wait(&cx).await.unwrap().all_handled());
            assert!(emitter.sync_notify(&cx, 4, EventBackpressure::Wait).await.unwrap().all_handled());
            assert!(!log.events.lock().iter().any(|(_, _, event)| *event == 3));
            assert!(manager.shutdown().await.close.is_ok());
        });
    }
}

#[test]
fn native_abandoned_fanout_releases_routing_gate_before_rollback_wakes() {
    struct Probe {
        shared: Arc<Shared<u64>>,
        observed_unlocked: AtomicBool,
    }
    impl std::task::Wake for Probe {
        fn wake(self: Arc<Self>) { self.wake_by_ref(); }
        fn wake_by_ref(self: &Arc<Self>) {
            self.observed_unlocked.store(self.shared.gate.try_write().is_ok(), Ordering::Release);
        }
    }
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let log = Arc::new(Log::default());
            let hold = Arc::new(Latch::default());
            let a = Plan::new("a", &log);
            let mut b = Plan::new("b", &log);
            b.hold = Some((1, Arc::clone(&hold)));
            let mut manager = EventManager::open(&cx, EventManagerConfig::new(2, 1, 4)).await.unwrap();
            let a = manager.add_handler(&cx, "a", policy(), a.factory()).await.unwrap();
            a.ready(&cx).await.unwrap();
            manager.add_handler(&cx, "b", policy(), b.factory()).await.unwrap().ready(&cx).await.unwrap();
            let emitter = manager.emitter();
            let first = emitter.notify(&cx, 1, EventBackpressure::Wait).await.unwrap();
            hold.wait_parked().await;
            let second = emitter.notify(&cx, 2, EventBackpressure::Wait).await.unwrap();
            log.saw("a", 2).await;
            let mut notifying = Box::pin(emitter.notify(&cx, 3, EventBackpressure::Wait));
            poll_fn(|task| { assert!(notifying.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            let sender = emitter.shared.routes.lock().get(&a.id()).unwrap().sender.clone();
            let probe = Arc::new(Probe { shared: Arc::clone(&emitter.shared), observed_unlocked: AtomicBool::new(false) });
            let waker = std::task::Waker::from(Arc::clone(&probe));
            let mut waiting = Box::pin(sender.reserve_checked(&cx));
            assert!(waiting.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending(),
                "the abandoned notification must already own the first mailbox slot");
            drop(notifying);
            assert!(probe.observed_unlocked.load(Ordering::Acquire),
                "rollback must not wake a blocked producer under the routing gate");
            drop(waiting);
            assert!(!log.events.lock().iter().any(|(_, _, event)| *event == 3));
            hold.release();
            assert!(first.wait(&cx).await.unwrap().all_handled());
            assert!(second.wait(&cx).await.unwrap().all_handled());
            assert!(emitter.sync_notify(&cx, 4, EventBackpressure::Wait).await.unwrap().all_handled());
            assert!(manager.shutdown().await.close.is_ok());
        });
    }
}

#[test]
fn native_full_refusal_is_atomic_and_event_credit_lives_through_processing() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            assert!(matches!(EventManager::<u64, &'static str>::open(&cx,
                EventManagerConfig::new(0, 1, 1)).await, Err(EventManagerError::InvalidConfig)));
            let log = Arc::new(Log::default());
            let hold = Arc::new(Latch::default());
            let a = Plan::new("a", &log);
            let mut b = Plan::new("b", &log);
            b.hold = Some((1, Arc::clone(&hold)));
            let mut manager = EventManager::open(&cx, EventManagerConfig::new(2, 1, 2)).await.unwrap();
            manager.add_handler(&cx, "a", policy(), a.factory()).await.unwrap().ready(&cx).await.unwrap();
            manager.add_handler(&cx, "b", policy(), b.factory()).await.unwrap().ready(&cx).await.unwrap();
            let emitter = manager.emitter();
            let first = emitter.notify(&cx, 1, EventBackpressure::Wait).await.unwrap();
            hold.wait_parked().await;
            let second = emitter.notify(&cx, 2, EventBackpressure::Wait).await.unwrap();
            log.saw("a", 2).await;
            assert!(matches!(emitter.notify(&cx, 3, EventBackpressure::Reject).await, Err(EventManagerError::Busy)));
            assert!(matches!(manager.add_handler(&cx, "too-many", policy(), Plan::new("extra", &log).factory()).await,
                Err(EventManagerError::Supervisor(DynamicSupervisorError::Capacity))));
            assert!(!emitter.shared.closed.load(Ordering::Acquire), "preflight refusal must not stop existing work");
            hold.release();
            assert!(first.wait(&cx).await.unwrap().all_handled());
            assert!(second.wait(&cx).await.unwrap().all_handled());
            assert_eq!(emitter.in_flight(), 0, "retaining settled receipts must not retain admission credit");
            assert!(emitter.sync_notify(&cx, 4, EventBackpressure::Reject).await.unwrap().all_handled());
            assert!(manager.shutdown().await.close.is_ok());
        });
    }
}

async fn failure_isolation(cx: Cx, panic: bool) {
    let log = Arc::new(Log::default());
    let mut a = Plan::new("a", &log);
    a.fail = Some(7); a.panic = panic;
    let starts = Arc::clone(&a.starts);
    let b = Plan::new("b", &log);
    let mut manager = EventManager::open(&cx, EventManagerConfig::new(2, 2, 4)).await.unwrap();
    let a = manager.add_handler(&cx, "a", policy(), a.factory()).await.unwrap();
    let b = manager.add_handler(&cx, "b", policy(), b.factory()).await.unwrap();
    let a_first = a.ready(&cx).await.unwrap();
    let b_first = b.ready(&cx).await.unwrap();
    let emitter = manager.emitter();
    let report = emitter.sync_notify(&cx, 7, EventBackpressure::Wait).await.unwrap();
    assert_eq!(report.recipients[0].status, if panic { EventStatus::Panicked } else { EventStatus::Failed });
    assert_eq!(report.recipients[1].status, EventStatus::Handled);
    a.state.changed.wait_until(|| a.state.initialized.lock().is_some_and(|g| g.number == 2)).await;
    let a_next = a.ready(&cx).await.unwrap();
    assert_ne!(a_first.task, a_next.task);
    assert_ne!(a_first.region, a_next.region);
    assert_eq!(starts.load(Ordering::Acquire), 2);
    let report = emitter.sync_notify(&cx, 8, EventBackpressure::Wait).await.unwrap();
    assert!(report.all_handled());
    assert_eq!(report.recipients[0].generation, Some(a_next));
    assert_eq!(report.recipients[1].generation, Some(b_first));
    let report = manager.shutdown().await;
    assert_eq!(report.children.len(), 2);
    assert!(report.close.is_ok());
}

#[test]
fn native_handler_errors_and_panics_restart_without_restarting_siblings() {
    for workers in [1, 2] {
        for panic in [false, true] { native(workers, move |cx| failure_isolation(cx, panic)); }
    }
}

#[test]
fn native_swap_buffers_emissions_until_old_termination_and_region_drain() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let log = Arc::new(Log::default());
            let cleanup = Arc::new(Latch::default());
            let mut old = Plan::new("old", &log);
            old.terminate = Some(Arc::clone(&cleanup));
            let next = Plan::new("new", &log);
            let new_starts = Arc::clone(&next.starts);
            let mut manager = EventManager::open(&cx, EventManagerConfig::new(1, 1, 2)).await.unwrap();
            let old = manager.add_handler(&cx, "handler", policy(), old.factory()).await.unwrap();
            old.ready(&cx).await.unwrap();
            let emitter = manager.emitter();
            assert!(emitter.sync_notify(&cx, 10, EventBackpressure::Wait).await.unwrap().all_handled());
            let mut swapping = cx.spawn(move |cx| async move {
                let (next, retired) = manager.swap_handler(&cx, &old, policy(), next.factory()).await.unwrap();
                (manager, next, retired)
            }).unwrap();
            cleanup.wait_parked().await;
            assert_eq!(new_starts.load(Ordering::Acquire), 0);
            let parked = Arc::new(Latch::default());
            let witnessed = Arc::clone(&parked);
            let child_emitter = emitter.clone();
            let mut emitting = cx.spawn(move |cx| async move {
                let mut wait = std::pin::pin!(child_emitter.notify(&cx, 20, EventBackpressure::Wait));
                poll_fn(|task| {
                    let result = wait.as_mut().poll(task);
                    if result.is_pending() && !witnessed.parked.swap(true, Ordering::AcqRel) {
                        witnessed.observed.notify_waiters();
                    }
                    result
                }).await.unwrap()
            }).unwrap();
            parked.wait_parked().await;
            assert_eq!(emitter.in_flight(), 1);
            assert!(!log.events.lock().iter().any(|(_, _, event)| *event == 20));
            cleanup.release();
            let (manager, next, retired) = swapping.join(&cx).await.unwrap();
            assert!(retired.close.is_ok());
            let report = emitting.join(&cx).await.unwrap().wait(&cx).await.unwrap();
            assert!(report.all_handled());
            assert_eq!(report.recipients[0].handler.id(), next.id());
            assert_eq!(new_starts.load(Ordering::Acquire), 1);
            assert!(log.events.lock().iter().any(|(label, _, event)| *label == "new" && *event == 20));
            assert!(!log.events.lock().iter().any(|(label, _, event)| *label == "old" && *event == 20));
            assert!(manager.shutdown().await.close.is_ok());
        });
    }
}

#[test]
fn native_abandoned_swap_seals_emission_and_shutdown_retains_cleanup_ownership() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let log = Arc::new(Log::default());
            let cleanup = Arc::new(Latch::default());
            let mut old = Plan::new("old", &log);
            old.terminate = Some(Arc::clone(&cleanup));
            let next = Plan::new("new", &log);
            let starts = Arc::clone(&next.starts);
            let mut manager = EventManager::open(&cx, EventManagerConfig::new(1, 1, 2)).await.unwrap();
            let old = manager.add_handler(&cx, "handler", policy(), old.factory()).await.unwrap();
            old.ready(&cx).await.unwrap();
            let emitter = manager.emitter();
            let mut swap = Box::pin(manager.swap_handler(&cx, &old, policy(), next.factory()));
            let mut observed = std::pin::pin!(cleanup.wait_parked());
            poll_fn(|task| {
                assert!(swap.as_mut().poll(task).is_pending());
                observed.as_mut().poll(task)
            }).await;
            drop(swap);
            assert!(matches!(emitter.notify(&cx, 1, EventBackpressure::Wait).await, Err(EventManagerError::Closed)));
            let mut shutdown = Box::pin(manager.shutdown());
            poll_fn(|task| { assert!(shutdown.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            assert_eq!(starts.load(Ordering::Acquire), 0);
            cleanup.release();
            let report = shutdown.await;
            assert_eq!(report.children.len(), 1);
            assert!(report.close.is_ok());
            assert_eq!(starts.load(Ordering::Acquire), 0);
            assert_eq!(emitter.in_flight(), 0);
        });
    }
}

#[test]
fn native_failed_terminate_forbids_replacement_but_other_handlers_continue() {
    for workers in [1, 2] {
      for drop_panic in [false, true] {
        native(workers, move |cx| async move {
            let log = Arc::new(Log::default());
            let mut bad = Plan::new("bad", &log);
            bad.fail = Some(7); bad.terminate_error = !drop_panic; bad.drop_panic = drop_panic;
            let starts = Arc::clone(&bad.starts);
            let mut manager = EventManager::open(&cx, EventManagerConfig::new(2, 2, 4)).await.unwrap();
            let bad = manager.add_handler(&cx, "bad", policy(), bad.factory()).await.unwrap();
            let good = manager.add_handler(&cx, "good", policy(), Plan::new("good", &log).factory()).await.unwrap();
            bad.ready(&cx).await.unwrap(); good.ready(&cx).await.unwrap();
            let emitter = manager.emitter();
            let report = emitter.sync_notify(&cx, 7, EventBackpressure::Wait).await.unwrap();
            assert_eq!(report.recipients[0].status, EventStatus::Failed);
            assert_eq!(report.recipients[1].status, EventStatus::Handled);
            bad.state.changed.wait_until(|| bad.is_closed()).await;
            assert_eq!(starts.load(Ordering::Acquire), 1);
            let report = emitter.sync_notify(&cx, 8, EventBackpressure::Wait).await.unwrap();
            assert!(report.all_handled());
            assert_eq!(report.recipients.len(), 1);
            assert_eq!(report.recipients[0].handler.id(), good.id());
            let report = manager.shutdown().await;
            let bad = report.children.iter().find(|c| c.id.name() == "bad").unwrap();
            let supervised = bad.supervisor.as_ref().unwrap();
            assert_eq!(supervised.restart_batches, 0);
            assert_eq!(supervised.started, 1);
            assert_eq!(supervised.joined, 1);
            assert_eq!(supervised.escalations, 1);
            if drop_panic {
                assert!(matches!(supervised.children[0].cleanup_outcome, Some(Outcome::Panicked(_))));
            } else {
                assert!(matches!(supervised.children[0].cleanup_outcome, Some(Outcome::Err(_))));
            }
            assert!(!cx.is_cancel_requested());
        });
      }
    }
}

#[test]
fn native_shutdown_cancels_parked_callback_and_waits_for_masked_termination() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let log = Arc::new(Log::default());
            let processing = Arc::new(Latch::default());
            let cleanup = Arc::new(Latch::default());
            let mut plan = Plan::new("held", &log);
            plan.hold = Some((1, Arc::clone(&processing)));
            plan.terminate = Some(Arc::clone(&cleanup));
            let mut manager = EventManager::open(&cx, EventManagerConfig::new(1, 1, 1)).await.unwrap();
            let handler = manager.add_handler(&cx, "held", policy(), plan.factory()).await.unwrap();
            handler.ready(&cx).await.unwrap();
            let receipt = manager.emitter().notify(&cx, 1, EventBackpressure::Wait).await.unwrap();
            processing.wait_parked().await;
            let mut shutdown = Box::pin(manager.shutdown());
            let mut observed = std::pin::pin!(cleanup.wait_parked());
            poll_fn(|task| {
                assert!(shutdown.as_mut().poll(task).is_pending());
                observed.as_mut().poll(task)
            }).await;
            assert!(handler.state.initialized.lock().is_none());
            assert_eq!(receipt.wait(&cx).await.unwrap().recipients[0].status, EventStatus::Cancelled);
            assert_eq!(log.terminations.lock()[0].2, EventStopReason::Cancelled);
            cleanup.release();
            assert!(shutdown.await.close.is_ok());
            assert!(handler.is_closed());
        });
    }
}

#[test]
fn native_dropped_manager_retains_cleanup_under_its_enclosing_region() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let log = Arc::new(Log::default());
            let cleanup = Arc::new(Latch::default());
            let mut plan = Plan::new("owned", &log);
            plan.terminate = Some(Arc::clone(&cleanup));
            let region = cx.open_child_region(crate::cx::ChildRegionSpec::inherit()).await.unwrap();
            let mut owner = region.cx().spawn(move |cx| async move {
                let mut manager = EventManager::open(&cx, EventManagerConfig::new(1, 1, 1)).await.unwrap();
                let handler = manager.add_handler(&cx, "owned", policy(), plan.factory()).await.unwrap();
                handler.ready(&cx).await.unwrap();
                let emitter = manager.emitter();
                assert!(emitter.sync_notify(&cx, 1, EventBackpressure::Wait).await.unwrap().all_handled());
                drop(manager);
                (emitter, handler)
            }).unwrap();
            let (emitter, handler) = owner.join(&cx).await.unwrap();
            cleanup.wait_parked().await;
            assert!(matches!(emitter.notify(&cx, 2, EventBackpressure::Wait).await, Err(EventManagerError::Closed)));
            let mut closing = Box::pin(region.close());
            poll_fn(|task| { assert!(closing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            assert!(!handler.is_closed(), "retirement cannot precede asynchronous cleanup");
            cleanup.release();
            closing.await.unwrap();
            assert!(handler.is_closed());
            assert_eq!(log.terminations.lock().as_slice(), &[("owned", 1, EventStopReason::Cancelled)]);
            assert_eq!(emitter.in_flight(), 0);
            assert!(!cx.is_cancel_requested());
        });
    }
}

#[test]
fn lab_event_fanout_restart_and_cleanup_reach_quiescence() {
    for seed in [17, 41, 93] {
      for panic in [false, true] {
        let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(16384));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
            failure_isolation(Cx::current().unwrap(), panic).await;
        }).unwrap();
        lab.scheduler.lock().schedule(task, 0);
        let virtual_time = lab.run_with_auto_advance();
        let report = lab.run_until_quiescent_with_report();
        assert!(matches!(join.try_join(), Ok(Some(()))), "seed={seed}: {virtual_time:?} {report:?}");
        assert!(lab.state.tasks_is_empty());
        assert!(lab.state.obligations_iter().all(|(_, obligation)| !obligation.is_pending()));
        assert!(report.lab_test_passed(), "seed={seed}: {report:?}");
      }
    }
}
