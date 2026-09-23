//! Native child-context race cancellation and drain, not a source-text proxy.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::Cx;
use asupersync::channel::mpsc;
use asupersync::cx::{RaceFactory, cap};
use asupersync::runtime::{JoinError, RuntimeBuilder};
use asupersync::sync::Notify;
use asupersync::types::{CancelKind, TaskId};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

#[derive(Default)]
struct Witness {
    parked: AtomicBool,
    cancelled: AtomicBool,
    released: AtomicBool,
    retired: AtomicBool,
    task: Mutex<Option<TaskId>>,
    changed: Notify,
}
impl Witness {
    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}
struct Retire(Arc<Witness>);
impl Drop for Retire {
    fn drop(&mut self) {
        self.0.retired.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }
}

fn boxed<T, F, Fut>(factory: F) -> RaceFactory<T>
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
{
    Box::new(move |child| Box::pin(factory(child)))
}

fn native<F, Fut>(workers: usize, body: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread().build().unwrap()
    } else {
        RuntimeBuilder::new().worker_threads(workers).build().unwrap()
    };
    let result = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("real admitted native task");
        asupersync::time::timeout(cx.now(), Duration::from_secs(10), body(cx.clone()))
            .await.expect("native race/drain watchdog");
    }));
    assert!(result.is_ok(), "native owner failed: {result:?}");
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

async fn loser(child: Cx, mut receiver: mpsc::Receiver<()>, seen: Arc<Witness>) -> u8 {
    let _retire = Retire(Arc::clone(&seen));
    *seen.task.lock().unwrap() = Some(child.task_id());
    let result = {
        let mut receive = std::pin::pin!(receiver.recv(&child));
        poll_fn(|task| {
            let progress = receive.as_mut().poll(task);
            if progress.is_pending() && !seen.parked.swap(true, Ordering::AcqRel) {
                seen.changed.notify_waiters();
            }
            progress
        }).await
    };
    // The sender is still retained by the owner and never sends. Only the
    // branch's actual cancellation can release this witnessed pending receive.
    assert!(result.is_err());
    assert!(child.is_cancel_requested());
    assert_eq!(child.cancel_reason().unwrap().kind, CancelKind::RaceLost);
    assert!(child.checkpoint().is_err());
    seen.cancelled.store(true, Ordering::Release);
    seen.changed.notify_waiters();
    // Deliberately asynchronous cleanup, withheld until the owner verifies
    // that neither ordinary selection nor timeout published an early result.
    seen.changed.wait_until(|| seen.released.load(Ordering::Acquire)).await;
    0
}

async fn winner(seen: Arc<Witness>) -> u8 {
    seen.changed.wait_until(|| seen.parked.load(Ordering::Acquire)).await;
    7
}

async fn wait_cancel<T>(future: &mut Pin<Box<impl Future<Output = T>>>, seen: &Witness) {
    let mut cancelled = std::pin::pin!(seen.changed.wait_until(|| seen.cancelled.load(Ordering::Acquire)));
    poll_fn(|task| {
        assert!(future.as_mut().poll(task).is_pending(), "race returned before withheld cleanup");
        cancelled.as_mut().poll(task)
    }).await;
    assert!(!seen.retired.load(Ordering::Acquire));
}

#[test]
fn factories_cancel_the_real_child_and_await_its_cleanup_on_both_native_runtimes() {
    for workers in [1, 2] {
        native(workers, move |cx| async move {
            let start = Instant::now();
            let seen = Arc::new(Witness::default());
            let (_sender, receiver) = mpsc::channel(1);
            let a = Arc::clone(&seen);
            let b = Arc::clone(&seen);
            let mut race = Box::pin(cx.race_drained_with(vec![
                boxed(move |child| loser(child, receiver, a)),
                boxed(move |_child| winner(b)),
            ]));
            wait_cancel(&mut race, &seen).await;
            assert_ne!(seen.task.lock().unwrap().unwrap(), cx.task_id());
            assert!(!cx.is_cancel_requested());
            seen.release();
            assert_eq!(race.await.unwrap(), 7);
            assert!(seen.retired.load(Ordering::Acquire));
            eprintln!("scenario=factory-recv workers={workers} parent={:?} child={:?} parked=true cancelled=true retired=true elapsed={:?}", cx.task_id(), *seen.task.lock().unwrap(), start.elapsed());
        });
    }
}

#[test]
fn timeout_waits_for_both_parked_losers_to_finish_cleanup() {
    for workers in [1, 2] {
        native(workers, move |cx| async move {
            let start = Instant::now();
            let a = Arc::new(Witness::default());
            let b = Arc::new(Witness::default());
            let (_sa, ra) = mpsc::channel(1);
            let (_sb, rb) = mpsc::channel(1);
            let fa = Arc::clone(&a);
            let fb = Arc::clone(&b);
            let mut race = Box::pin(cx.race_drained_with_timeout(Duration::from_millis(500), vec![
                boxed(move |child| loser(child, ra, fa)),
                boxed(move |child| loser(child, rb, fb)),
            ]));
            wait_cancel(&mut race, &a).await;
            wait_cancel(&mut race, &b).await;
            assert!(a.parked.load(Ordering::Acquire) && b.parked.load(Ordering::Acquire));
            a.release();
            b.release();
            assert!(matches!(race.await, Err(JoinError::Cancelled(reason)) if reason.kind == CancelKind::Timeout));
            assert!(a.retired.load(Ordering::Acquire) && b.retired.load(Ordering::Acquire));
            assert!(!cx.is_cancel_requested());
            eprintln!("scenario=factory-timeout workers={workers} cancelled=2 retired=2 elapsed={:?}", start.elapsed());
        });
    }
}

#[test]
fn loser_cleanup_panic_is_not_hidden_by_a_successful_winner() {
    for workers in [1, 2] {
        native(workers, move |cx| async move {
            let seen = Arc::new(Witness::default());
            let (_sender, receiver) = mpsc::channel(1);
            let a = Arc::clone(&seen);
            let b = Arc::clone(&seen);
            let mut race = Box::pin(cx.race_drained_with(vec![
                boxed(move |child| async move {
                    loser(child, receiver, a).await;
                    panic!("factory loser cleanup sentinel");
                }),
                boxed(move |_child| winner(b)),
            ]));
            wait_cancel(&mut race, &seen).await;
            seen.release();
            assert!(matches!(race.await, Err(JoinError::Panicked(_))));
            assert!(seen.retired.load(Ordering::Acquire));
        });
    }
}

#[test]
fn cancelled_and_masked_owners_never_invoke_a_factory() {
    native(1, |cx| async move {
        let denied = {
            let _guard = cx.clone().restrict::<cap::CapSet<false, true, true, true, true>>()
                .set_current_restricted();
            Cx::current().unwrap()
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let result = denied.race_drained_with(vec![boxed(move |_child| {
            observed.fetch_add(1, Ordering::SeqCst);
            async { 1 }
        })]).await;
        assert!(matches!(result, Err(JoinError::Cancelled(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    });
    let cx = Cx::detached_cancel_context();
    cx.cancel_fast(CancelKind::User);
    let mut future = Box::pin(cx.race_drained_with(vec![boxed::<(), _, _>(|_child| async {
        panic!("cancelled owner must not invoke its factory");
    })]));
    assert!(matches!(future.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop())),
        Poll::Ready(Err(JoinError::Cancelled(reason))) if reason.kind == CancelKind::User));
}

#[cfg(feature = "proc-macros")]
#[test]
fn race_macro_factory_forms_share_native_cancel_and_drain_semantics() {
    for workers in [1, 2] {
        for form in 0..4 {
            native(workers, move |cx| async move {
                let seen = Arc::new(Witness::default());
                let (_sender, receiver) = mpsc::channel(1);
                let a = Arc::clone(&seen);
                let b = Arc::clone(&seen);
                let run = async {
                    match form {
                        0 => asupersync::race!(cx, {
                            move |child| loser(child, receiver, a),
                            move |_child| winner(b),
                        }),
                        1 => asupersync::race!(cx, {
                            "parked" => move |child| loser(child, receiver, a),
                            "winner" => move |_child| winner(b),
                        }),
                        2 => asupersync::race!(cx, timeout: Duration::from_secs(5), {
                            move |child| loser(child, receiver, a),
                            move |_child| winner(b),
                        }),
                        _ => asupersync::race!(cx, timeout: Duration::from_secs(5), {
                            "parked" => move |child| loser(child, receiver, a),
                            "winner" => move |_child| winner(b),
                        }),
                    }
                };
                let mut race = Box::pin(run);
                wait_cancel(&mut race, &seen).await;
                seen.release();
                assert_eq!(race.await.unwrap(), 7);
                assert!(seen.retired.load(Ordering::Acquire));
                assert!(!cx.is_cancel_requested());
                eprintln!("scenario=macro-factory workers={workers} form={form} parked=true cancelled=true retired=true");
            });
        }
    }
}
