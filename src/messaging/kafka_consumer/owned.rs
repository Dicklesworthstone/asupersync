//! An admitted blocking worker owns the native consumer from construction through
//! destruction. Async code receives a borrowing lease, never the last native Arc.

use super::{ConsumerConfig, KafkaConsumer, KafkaError};
use crate::cx::resource_bracket::{BracketConfig, BracketHandle, BracketUseFuture};
#[cfg(feature = "kafka")]
use crate::cx::CancelWakerToken;
use crate::cx::Cx;
#[cfg(feature = "kafka")]
use crate::runtime::blocking_pool::BlockingPoolHandle;
use crate::runtime::blocking_pool::BlockingTaskHandle;
use crate::runtime::SpawnError;
use crate::types::Outcome;
use parking_lot::{Condvar, Mutex};
use std::future::poll_fn;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

/// A region-owned Kafka invocation, including its final native destruction.
/// Inspect the bracket's use, close, and release results separately.
pub type KafkaConsumerHandle<T> = BracketHandle<KafkaConsumerLease, T, KafkaError, KafkaError>;

/// Opaque ownership retained by a scoped consumer's lifecycle controller.
///
/// Application code borrows the underlying [`KafkaConsumer`] through
/// [`KafkaConsumer::spawn_scoped`]. Dropping this lease only signals the already
/// admitted blocking worker; it never polls librdkafka or starts another thread.
/// A bracket report with `unreleased: Some(...)` has not established region
/// quiescence. Retain that lease until its users have stopped, as required by the
/// bracket contract.
pub struct KafkaConsumerLease {
    consumer: Option<Arc<KafkaConsumer>>,
    lifetime: Arc<Lifetime>,
}

impl std::fmt::Debug for KafkaConsumerLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaConsumerLease")
            .field("released", &self.consumer.is_none())
            .finish_non_exhaustive()
    }
}

impl KafkaConsumerLease {
    fn release(&mut self) {
        // The worker is allowed to destroy its retained owner only AFTER this
        // reference has been retired. Reversing these operations moves the last
        // native destructor back onto the async caller in the release race.
        drop(self.consumer.take());
        self.lifetime.stop();
    }

    async fn finish(mut self) -> Result<(), KafkaError> {
        self.release();
        poll_fn(|cx| self.lifetime.poll_finished(cx)).await
    }
}

impl Drop for KafkaConsumerLease {
    fn drop(&mut self) {
        self.release();
    }
}

impl KafkaConsumer {
    /// Run a borrowing consumer body with region-owned native teardown.
    ///
    /// Construction, waiting for all outstanding native calls, group leave, and
    /// final librdkafka destruction occur on one blocking-pool worker. The body
    /// may call the existing consumer methods; its return, error, panic, or
    /// cooperative cancellation is followed by child-region drain and release.
    /// Dropping the returned handle requests cancellation while the admitted
    /// controller retains cleanup. `join()` supplies the native destruction
    /// receipt through the bracket's release outcome.
    ///
    /// This requires an explicitly configured runtime blocking pool (for example
    /// `RuntimeBuilder::new().blocking_threads(1, 4)`) and reserves one worker per
    /// live scoped consumer. Size the pool for simultaneously live consumers,
    /// including nested invocations, plus other blocking work. A missing or
    /// rejecting pool fails acquisition before constructing a native consumer;
    /// cleanup never falls back onto an async worker. A queued acquisition can
    /// be cancelled even when every pool worker is occupied. That cancellation
    /// fences native construction immediately; the pool may still retain the
    /// cancelled queue entry until a worker can retire its bookkeeping.
    /// The acquisition context must retain I/O authority; native broker sockets
    /// are opened by librdkafka on its own threads, not by the runtime reactor.
    ///
    /// The five-second revoke polling allowance is not a bound on an outstanding
    /// broker call or librdkafka's final destruction. Release waits for actual
    /// completion rather than reporting quiescence at a timer boundary. Native
    /// calls must eventually return; forced runtime teardown or process exit can
    /// still prevent a release receipt. The synchronous `new`/`Drop` contract is
    /// unchanged; this is the owned path for async applications.
    pub fn spawn_scoped<T, F>(
        cx: &Cx,
        config: ConsumerConfig,
        lifecycle: BracketConfig,
        body: F,
    ) -> Result<KafkaConsumerHandle<T>, SpawnError>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(Cx, &'a KafkaConsumer) -> BracketUseFuture<'a, T, KafkaError>
            + Send
            + 'static,
    {
        let pool = cx.blocking_pool_handle();
        #[cfg(feature = "kafka")]
        let io_allowed = io_allowed(cx);
        cx.spawn_bracket(
            lifecycle,
            move |acquire_cx| async move {
                #[cfg(not(feature = "kafka"))]
                {
                    let _ = (acquire_cx, pool, config);
                    Outcome::Err(KafkaError::FeatureDisabled)
                }
                #[cfg(feature = "kafka")]
                {
                    if !io_allowed {
                        return Outcome::Err(io_refusal());
                    }
                    match acquire(&acquire_cx, pool, config).await {
                        Ok(lease) => Outcome::Ok(lease),
                        Err(KafkaError::Cancelled) => Outcome::Cancelled(
                            acquire_cx.cancel_reason().unwrap_or_else(|| {
                                crate::types::CancelReason::user("Kafka acquisition cancelled")
                            }),
                        ),
                        Err(error) => Outcome::Err(error),
                    }
                }
            },
            move |body_cx, lease: &mut KafkaConsumerLease| {
                body(body_cx, lease.consumer.as_deref().expect("owned consumer before release"))
            },
            move |_release_cx, lease| async move {
                match lease.finish().await {
                    Ok(()) => Outcome::Ok(()),
                    Err(error) => Outcome::Err(error),
                }
            },
        )
    }
}

#[cfg(feature = "kafka")]
fn io_allowed(cx: &Cx) -> bool {
    cx.runtime_mask.has(crate::cx::cap::CapMask::IO)
        && Cx::current().is_none_or(|ambient| {
            ambient.runtime_mask.has(crate::cx::cap::CapMask::IO)
        })
}

#[cfg(feature = "kafka")]
fn io_refusal() -> KafkaError {
    KafkaError::Config("scoped Kafka consumers require I/O authority".to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Queued,
    #[cfg(feature = "kafka")]
    Starting,
    Finished,
}

struct LifetimeState {
    phase: Phase,
    stopped: bool,
    published: bool,
    acquired: Option<Result<Arc<KafkaConsumer>, KafkaError>>,
    finished: Option<Result<(), KafkaError>>,
    waiter: Option<Waker>,
}

struct Lifetime {
    state: Mutex<LifetimeState>,
    released: Condvar,
    task: Mutex<Option<BlockingTaskHandle>>,
    #[cfg(all(test, feature = "kafka"))]
    publication_hook: Mutex<Option<PublicationHook>>,
}

#[cfg(all(test, feature = "kafka"))]
struct PublicationHook {
    constructed: crate::channel::oneshot::Sender<(
        std::sync::Weak<rdkafka::consumer::BaseConsumer<super::BrokerConsumerContext>>,
        Arc<super::RebalanceCounters>,
        std::thread::ThreadId,
    )>,
    allow_publish: std::sync::mpsc::Receiver<()>,
    published: crate::channel::oneshot::Sender<()>,
    allow_cleanup: std::sync::mpsc::Receiver<()>,
}

impl Lifetime {
    #[cfg(feature = "kafka")]
    fn new() -> Self {
        Self {
            state: Mutex::new(LifetimeState {
                phase: Phase::Queued,
                stopped: false,
                published: false,
                acquired: None,
                finished: None,
                waiter: None,
            }),
            released: Condvar::new(),
            task: Mutex::new(None),
            #[cfg(test)]
            publication_hook: Mutex::new(None),
        }
    }

    fn stop(&self) {
        // Revoke publication before dropping an unclaimed acquisition. Its Arc
        // must disappear before the worker observes `stopped` and destroys its
        // own reference. The phase claim gate also makes queued cancellation
        // independent of an available worker.
        let acquired = {
            let mut state = self.state.lock();
            state.published = true;
            state.acquired.take()
        };
        drop(acquired);
        let wake = {
            let mut state = self.state.lock();
            state.stopped = true;
            if state.phase == Phase::Queued {
                state.phase = Phase::Finished;
                state.finished = Some(Ok(()));
            }
            self.released.notify_all();
            state.waiter.take()
        };
        if let Some(task) = self.task.lock().as_ref() {
            task.cancel();
        }
        if let Some(wake) = wake {
            wake.wake();
        }
    }

    fn poll_finished(&self, cx: &mut Context<'_>) -> Poll<Result<(), KafkaError>> {
        let next = cx.waker().clone();
        let mut state = self.state.lock();
        if let Some(result) = state.finished.take() {
            return Poll::Ready(result);
        }
        let old = state.waiter.replace(next);
        drop(state);
        drop(old);
        Poll::Pending
    }

    #[cfg(feature = "kafka")]
    fn finish(&self, error: Option<&str>) {
        let wake = {
            let mut state = self.state.lock();
            if state.phase == Phase::Finished {
                return;
            }
            state.phase = Phase::Finished;
            if !state.published {
                state.published = true;
                state.acquired = Some(Err(KafkaError::Config(
                    error.unwrap_or("Kafka worker completed before publishing a consumer").to_owned(),
                )));
            }
            state.finished = Some(match error {
                Some(error) => Err(KafkaError::Config(error.to_owned())),
                None => Ok(()),
            });
            state.waiter.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}

#[cfg(feature = "kafka")]
struct WorkerReceipt {
    lifetime: Arc<Lifetime>,
    started: bool,
    finished: bool,
}

#[cfg(feature = "kafka")]
impl Drop for WorkerReceipt {
    fn drop(&mut self) {
        if !self.finished {
            self.lifetime.finish(Some(if self.started {
                "Kafka lifetime worker panicked; native cleanup did not produce a success receipt"
            } else {
                "Kafka lifetime job was rejected before native construction"
            }));
        }
    }
}

#[cfg(feature = "kafka")]
fn run_worker(config: ConsumerConfig, mut receipt: WorkerReceipt) {
    {
        let mut state = receipt.lifetime.state.lock();
        if state.phase != Phase::Queued {
            return;
        }
        state.phase = Phase::Starting;
        receipt.started = true;
    }

    let consumer = match KafkaConsumer::new(config) {
        Ok(consumer) => Arc::new(consumer),
        Err(error) => {
            let wake = {
                let mut state = receipt.lifetime.state.lock();
                if !state.published {
                    state.published = true;
                    state.acquired = Some(Err(error));
                }
                state.waiter.take()
            };
            if let Some(wake) = wake {
                wake.wake();
            }
            receipt.lifetime.finish(None);
            receipt.finished = true;
            return;
        }
    };
    #[cfg(test)]
    let publication_hook = receipt.lifetime.publication_hook.lock().take();
    #[cfg(test)]
    let after_publication = publication_hook.map(|hook| {
        hook.constructed.send_blocking((
            Arc::downgrade(consumer.consumer.as_ref().expect("test uses native Kafka")),
            Arc::clone(&consumer.rebalance.as_ref().expect("native rebalance counters").1),
            std::thread::current().id(),
        )).unwrap();
        hook.allow_publish.recv_timeout(std::time::Duration::from_secs(20)).unwrap();
        (hook.published, hook.allow_cleanup)
    });
    let wake = {
        let mut state = receipt.lifetime.state.lock();
        if !state.published {
            state.published = true;
            state.acquired = Some(Ok(Arc::clone(&consumer)));
        }
        state.waiter.take()
    };
    #[cfg(test)]
    if let Some((published, allow_cleanup)) = after_publication {
        published.send_blocking(()).unwrap();
        allow_cleanup.recv_timeout(std::time::Duration::from_secs(20)).unwrap();
    }
    if let Some(wake) = wake {
        wake.wake();
    }
    {
        let mut state = receipt.lifetime.state.lock();
        while !state.stopped {
            receipt.lifetime.released.wait(&mut state);
        }
    }
    if let Some(operations) = &consumer.broker_ops {
        operations.retire_and_wait();
        // Admission is now fenced, so the legacy Drop cannot obtain a lease.
        // Perform its group-leave protocol here with the sole retained handle.
        if let Some(native) = &consumer.consumer {
            let _guard = operations.lock();
            super::leave_group_bounded(native);
        }
        consumer.closed.store(true, std::sync::atomic::Ordering::Release);
    }
    drop(consumer);
    receipt.lifetime.finish(None);
    receipt.finished = true;
}

#[cfg(feature = "kafka")]
struct Acquisition<'a> {
    cx: &'a Cx,
    lifetime: Arc<Lifetime>,
    cancel_token: Option<CancelWakerToken>,
    transferred: bool,
    cancelled: bool,
}

#[cfg(feature = "kafka")]
impl Drop for Acquisition<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.cancel_token.take() {
            self.cx.clear_cancel_waker(token);
        }
        if !self.transferred {
            self.lifetime.stop();
        }
        let old = self.lifetime.state.lock().waiter.take();
        drop(old);
    }
}

#[cfg(feature = "kafka")]
async fn acquire(
    cx: &Cx,
    pool: Option<BlockingPoolHandle>,
    config: ConsumerConfig,
) -> Result<KafkaConsumerLease, KafkaError> {
    acquire_on_lifetime(cx, pool, config, Arc::new(Lifetime::new())).await
}

#[cfg(feature = "kafka")]
async fn acquire_on_lifetime(
    cx: &Cx,
    pool: Option<BlockingPoolHandle>,
    config: ConsumerConfig,
    lifetime: Arc<Lifetime>,
) -> Result<KafkaConsumerLease, KafkaError> {
    cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
    if !io_allowed(cx) {
        return Err(io_refusal());
    }
    config.validate()?;
    let pool = pool.ok_or_else(|| KafkaError::Config(
        "scoped Kafka consumers require a configured blocking pool".to_owned(),
    ))?;
    let receipt = WorkerReceipt {
        lifetime: Arc::clone(&lifetime), started: false, finished: false,
    };
    // The queued closure owns only configuration. Native construction happens
    // after the worker wins the phase claim, never on a rejection fallback.
    let task = pool.spawn(move || run_worker(config, receipt));
    *lifetime.task.lock() = Some(task);
    let mut acquisition = Acquisition {
        cx, lifetime: Arc::clone(&lifetime), cancel_token: None,
        transferred: false, cancelled: false,
    };
    poll_fn(|task_cx| {
        acquisition.cancel_token = Some(cx.refresh_cancel_waker(acquisition.cancel_token, task_cx.waker()));
        if cx.checkpoint().is_err() && !acquisition.cancelled {
            acquisition.cancelled = true;
            lifetime.stop();
        }
        let next = task_cx.waker().clone();
        let mut state = lifetime.state.lock();
        if acquisition.cancelled {
            if state.phase == Phase::Finished {
                return Poll::Ready(Err(KafkaError::Cancelled));
            }
        } else if let Some(result) = state.acquired.take() {
            return Poll::Ready(result.map(|consumer| {
                acquisition.transferred = true;
                KafkaConsumerLease { consumer: Some(consumer), lifetime: Arc::clone(&lifetime) }
            }));
        }
        let old = state.waiter.replace(next);
        drop(state);
        drop(old);
        Poll::Pending
    }).await
}

#[cfg(all(test, feature = "kafka", not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::channel::oneshot;
    use crate::cx::ChildRegionSpec;
    use crate::runtime::RuntimeBuilder;
    use crate::types::Budget;
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    #[derive(Debug, Clone, Copy)]
    enum Stop {
        Return,
        Error,
        Panic,
        Cancel,
        DropHandle,
    }

    fn config() -> ConsumerConfig {
        let mut config = ConsumerConfig::new(
            vec!["127.0.0.1:1".to_owned()], "owned-native-teardown",
        ).with_property("socket.timeout.ms", "1000");
        config.force_real_kafka = true;
        config
    }

    fn bounded(test: impl FnOnce() + Send + 'static) {
        let (send, receive) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
            let _ = send.send(result);
        });
        let result = receive.recv_timeout(Duration::from_secs(30))
            .expect("scoped Kafka lifecycle must finish native destruction");
        thread.join().unwrap();
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    fn native_operation_drain(multithread: bool, stop: Stop) {
        let (send_operations, await_operations) =
            std::sync::mpsc::channel::<Arc<super::super::BrokerOperations>>();
        let (held, mut wait_held) = oneshot::channel();
        let (unlock, await_unlock) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let operations = await_operations.recv_timeout(Duration::from_secs(10)).unwrap();
            let _lock = operations.serial.lock();
            held.send_blocking(()).unwrap();
            await_unlock.recv_timeout(Duration::from_secs(20)).unwrap();
        });
        let builder = if multithread {
            RuntimeBuilder::new().worker_threads(2)
        } else {
            RuntimeBuilder::current_thread()
        };
        let runtime = builder.blocking_threads(1, 2).build().unwrap();
        let owner = runtime.request_cx_with_budget(Budget::INFINITE);
        runtime.block_on_with_cx(owner.clone(), async move {
            let enclosing = owner.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            let (parked, mut wait_parked) = oneshot::channel();
            let handle = KafkaConsumer::spawn_scoped(
                enclosing.cx(), config(), BracketConfig::new(u32::MAX),
                move |body_cx, consumer| -> BracketUseFuture<'_, u32, KafkaError> {
                    Box::pin(async move {
                        let native = Arc::downgrade(consumer.consumer.as_ref().unwrap());
                        let counters = Arc::clone(&consumer.rebalance.as_ref().unwrap().1);
                        let operations = Arc::clone(consumer.broker_ops.as_ref().unwrap());
                        send_operations.send(Arc::clone(&operations)).unwrap();
                        wait_held.recv(&body_cx).await.unwrap();
                        let (attempted, mut wait_attempted) = oneshot::channel();
                        *operations.before_lock.lock() = Some(attempted);
                        let topics = ["owned-teardown-topic"];
                        let mut subscribing = Box::pin(consumer.subscribe(&body_cx, &topics));
                        let mut attempted = Box::pin(wait_attempted.recv(&body_cx));
                        poll_fn(|task_cx| {
                            assert!(subscribing.as_mut().poll(task_cx).is_pending());
                            attempted.as_mut().poll(task_cx)
                        }).await.unwrap();
                        // The actual broker operation has entered BrokerOperations::lock
                        // while its mutex is held. Retiring this real subscribe future
                        // leaves a native blocking call outstanding.
                        parked.send_blocking((
                            native, counters, operations, std::thread::current().id(),
                        )).unwrap();
                        match stop {
                            Stop::Cancel | Stop::DropHandle => {
                                body_cx.cancelled().await;
                                assert!(body_cx.checkpoint().is_err());
                                drop(subscribing);
                                Outcome::Cancelled(body_cx.cancel_reason().unwrap())
                            }
                            Stop::Return => {
                                drop(subscribing);
                                Outcome::Ok(73)
                            }
                            Stop::Error => {
                                drop(subscribing);
                                Outcome::Err(KafkaError::Broker("body error retained".to_owned()))
                            }
                            Stop::Panic => panic!("scoped Kafka body panic"),
                        }
                    })
                },
            ).unwrap();
            let (native, counters, operations, body_thread) = wait_parked.recv(&owner).await.unwrap();
            let mut handle = match stop {
                Stop::DropHandle => { drop(handle); None }
                Stop::Cancel => { handle.abort(); Some(handle) }
                _ => Some(handle),
            };
            let trigger = Instant::now();
            loop {
                let retiring = operations.lifetime.lock().retiring;
                if retiring { break; }
                assert!(trigger.elapsed() < Duration::from_secs(10), "release never fenced native admission");
                crate::runtime::yield_now::yield_now().await;
            }
            assert!(operations.lifetime.lock().leases > 0, "blocked native call must remain owned");
            assert!(native.upgrade().is_some(), "cannot destroy native state under a live operation");
            assert!(counters.native_drop_thread.lock().is_none());
            let mut sibling = owner.spawn(|_| async { 29 }).unwrap();
            assert_eq!(sibling.join(&owner).await.unwrap(), 29, "executor must run while teardown waits");
            if let Some(handle) = &mut handle {
                let mut joining = Box::pin(handle.join());
                assert!(joining.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
            }
            unlock.send(()).unwrap();
            if let Some(handle) = &mut handle {
                let report = handle.join().await.unwrap();
                assert!(report.acquisition.as_ref().unwrap().is_success());
                assert!(report.close.as_ref().unwrap().is_ok());
                assert!(report.release.as_ref().unwrap().is_success());
                assert!(report.unreleased.is_none());
                assert!(report.infrastructure.is_empty());
                assert!(report.controller_task.is_ok());
                match stop {
                    Stop::Return => {
                        assert!(matches!(report.usage.as_ref().unwrap().outcome, Outcome::Ok(73)));
                        assert!(report.is_success());
                    }
                    Stop::Error => assert!(matches!(&report.usage.as_ref().unwrap().outcome,
                        Outcome::Err(KafkaError::Broker(message)) if message == "body error retained")),
                    Stop::Panic => assert!(matches!(report.usage.as_ref().unwrap().outcome, Outcome::Panicked(_))),
                    Stop::Cancel => {
                        assert!(report.usage.as_ref().unwrap().outcome.is_cancelled());
                        assert!(report.cancellation.is_some());
                    }
                    Stop::DropHandle => unreachable!(),
                }
            }
            enclosing.close().await.unwrap();
            assert!(native.upgrade().is_none(), "join must follow the final native destructor");
            assert_eq!(operations.lifetime.lock().leases, 0);
            let destruction = counters.native_drop_thread.lock().clone().unwrap();
            assert_ne!(destruction.0, body_thread, "native destructor cannot run on async body thread");
            assert!(destruction.1.as_deref().unwrap().contains("-blocking-"));
        });
        holder.join().unwrap();
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    }

    #[test]
    fn scoped_kafka_native_destructor_drains_cancelled_operations_off_executor() {
        for multithread in [false, true] {
            for stop in [Stop::Return, Stop::Error, Stop::Panic, Stop::Cancel, Stop::DropHandle] {
                bounded(move || native_operation_drain(multithread, stop));
            }
        }
    }

    #[test]
    fn scoped_kafka_queued_cancellation_does_not_wait_for_an_occupied_pool() {
        for multithread in [false, true] {
            bounded(move || {
                let builder = if multithread {
                    RuntimeBuilder::new().worker_threads(2)
                } else {
                    RuntimeBuilder::current_thread()
                };
                let runtime = builder.blocking_threads(1, 1).build().unwrap();
                let owner = runtime.request_cx_with_budget(Budget::INFINITE);
                let pool = runtime.blocking_handle().unwrap();
                let (held, mut wait_held) = oneshot::channel();
                let (unlock, await_unlock) = std::sync::mpsc::channel();
                let blocker = pool.spawn(move || {
                    held.send_blocking(()).unwrap();
                    await_unlock.recv_timeout(Duration::from_secs(20)).unwrap();
                });
                let called = Arc::new(AtomicBool::new(false));
                let observed = Arc::clone(&called);
                runtime.block_on_with_cx(owner.clone(), async move {
                    wait_held.recv(&owner).await.unwrap();
                    let enclosing = owner.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                    let mut handle = KafkaConsumer::spawn_scoped(
                        enclosing.cx(), config(), BracketConfig::new(u32::MAX),
                        move |_, _| -> BracketUseFuture<'_, (), KafkaError> {
                            Box::pin(async move { called.store(true, Ordering::Release); Outcome::Ok(()) })
                        },
                    ).unwrap();
                    let start = Instant::now();
                    while pool.pending_count() == 0 {
                        assert!(start.elapsed() < Duration::from_secs(10));
                        crate::runtime::yield_now::yield_now().await;
                    }
                    assert_eq!(pool.busy_threads(), 1, "sole worker is still held");
                    handle.abort();
                    let report = handle.join().await.unwrap();
                    assert!(report.acquisition.as_ref().unwrap().outcome.is_cancelled());
                    assert!(report.usage.is_none());
                    assert!(report.release.is_none(), "queued cancellation constructs no native consumer");
                    assert!(report.unreleased.is_none());
                    assert!(!blocker.is_done(), "cancelled acquisition must complete before worker unblocks");
                    enclosing.close().await.unwrap();
                    unlock.send(()).unwrap();
                });
                assert!(!observed.load(Ordering::Acquire));
                assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            });
        }
    }

    #[test]
    fn scoped_kafka_cancelled_unclaimed_publication_waits_for_native_destruction() {
        for multithread in [false, true] {
            bounded(move || {
                let builder = if multithread {
                    RuntimeBuilder::new().worker_threads(2)
                } else {
                    RuntimeBuilder::current_thread()
                };
                let runtime = builder.blocking_threads(1, 1).build().unwrap();
                let control = runtime.request_cx_with_budget(Budget::INFINITE);
                let caller = runtime.request_cx_with_budget(Budget::INFINITE);
                let pool = runtime.blocking_handle().unwrap();
                runtime.block_on_with_cx(control.clone(), async move {
                    let (constructed, mut wait_constructed) = oneshot::channel();
                    let (allow_publish, await_publish) = std::sync::mpsc::channel();
                    let (published, mut wait_published) = oneshot::channel();
                    let (allow_cleanup, await_cleanup) = std::sync::mpsc::channel();
                    let lifetime = Arc::new(Lifetime::new());
                    *lifetime.publication_hook.lock() = Some(PublicationHook {
                        constructed, allow_publish: await_publish,
                        published, allow_cleanup: await_cleanup,
                    });
                    // Exercise the exact acquisition implementation behind the
                    // public API. The hook gates only publication scheduling;
                    // construction, the worker job and final destructor are real.
                    let mut acquiring = Box::pin(acquire_on_lifetime(
                        &caller, Some(pool), config(), Arc::clone(&lifetime),
                    ));
                    assert!(acquiring.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
                    let (native, counters, worker) = wait_constructed.recv(&control).await.unwrap();
                    allow_publish.send(()).unwrap();
                    wait_published.recv(&control).await.unwrap();
                    assert!(matches!(lifetime.state.lock().acquired, Some(Ok(_))),
                        "must cancel a constructed, published, still unclaimed native owner");
                    caller.cancel_with(crate::types::CancelKind::User, Some("cancel unclaimed Kafka owner"));
                    assert!(acquiring.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
                        "started acquisition cancellation must wait for native destruction");
                    assert!(lifetime.state.lock().acquired.is_none());
                    assert!(native.upgrade().is_some());
                    assert!(counters.native_drop_thread.lock().is_none());
                    let mut sibling = control.spawn(|_| async { 41 }).unwrap();
                    assert_eq!(sibling.join(&control).await.unwrap(), 41);
                    allow_cleanup.send(()).unwrap();
                    assert!(matches!(acquiring.await, Err(KafkaError::Cancelled)));
                    assert!(caller.inner.read().cancel_waker_registrations.is_empty());
                    assert!(native.upgrade().is_none());
                    let destruction = counters.native_drop_thread.lock().clone().unwrap();
                    assert_eq!(destruction.0, worker, "unclaimed Arc must retire before the worker's pin");
                    assert!(destruction.1.as_deref().unwrap().contains("-blocking-"));
                });
            });
        }
    }

    #[test]
    fn scoped_kafka_refuses_missing_or_rejecting_pool_and_denied_io_before_construction() {
        for (rejected, denied_io) in [(false, false), (true, false), (false, true)] {
            bounded(move || {
                let runtime = RuntimeBuilder::current_thread().build().unwrap();
                let shutdown_pool = crate::runtime::blocking_pool::BlockingPool::new(0, 1);
                shutdown_pool.shutdown();
                let mut owner = runtime.request_cx_with_budget(Budget::INFINITE);
                if rejected {
                    owner = owner.with_blocking_pool_handle(Some(shutdown_pool.handle()));
                }
                if denied_io {
                    owner.runtime_mask = <crate::cx::cap::CapSet<true, true, true, false, true>
                        as crate::cx::cap::CapSetRuntimeMask>::MASK;
                }
                let called = Arc::new(AtomicBool::new(false));
                let observed = Arc::clone(&called);
                runtime.block_on_with_cx(owner.clone(), async move {
                    let mut handle = KafkaConsumer::spawn_scoped(
                        &owner, config(), BracketConfig::new(u32::MAX),
                        move |_, _| -> BracketUseFuture<'_, (), KafkaError> {
                            Box::pin(async move { called.store(true, Ordering::Release); Outcome::Ok(()) })
                        },
                    ).unwrap();
                    let report = handle.join().await.unwrap();
                    let expected = if denied_io {
                        "scoped Kafka consumers require I/O authority"
                    } else if rejected {
                        "Kafka lifetime job was rejected before native construction"
                    } else {
                        "scoped Kafka consumers require a configured blocking pool"
                    };
                    assert!(matches!(&report.acquisition.as_ref().unwrap().outcome,
                        Outcome::Err(KafkaError::Config(message)) if message == expected));
                    assert!(report.usage.is_none());
                    assert!(report.release.is_none());
                    assert!(report.unreleased.is_none());
                });
                assert!(!observed.load(Ordering::Acquire));
            });
        }
    }
}
