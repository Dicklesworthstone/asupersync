//! Real pool admission and retirement for offloaded receive sessions.

use super::*;
use crate::config::RaptorQConfig;
use crate::raptorq::RaptorQReceiverBuilder;
use crate::runtime::blocking_pool::{BlockingPoolHandle, BlockingTaskHandle};
use crate::runtime::{BlockingAdmissionPolicy, RootDrainOutcome, Runtime, RuntimeBuilder};
use crate::security::{AuthKey, AuthenticatedSymbol, SecurityContext};
use crate::transport::StreamError;
use crate::types::{Budget, ObjectId};
use std::collections::VecDeque;
use std::future::poll_fn;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(10);

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("offloaded receive scenario must finish within its wall watchdog");
    worker.join().unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

struct Source {
    symbols: VecDeque<AuthenticatedSymbol>,
    polls: Arc<AtomicUsize>,
}

impl SymbolStream for Source {
    fn poll_next(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(self.symbols.pop_front().map(Ok))
    }
}

fn config() -> RaptorQConfig {
    let mut config = RaptorQConfig::default();
    config.encoding.symbol_size = 64;
    config.encoding.max_block_size = 256;
    config.encoding.repair_overhead = 1.5;
    config
}

fn encoded(data: &[u8]) -> (ObjectParams, Vec<AuthenticatedSymbol>) {
    let object = ObjectId::new(71, 9);
    let config = config();
    let mut encoder = super::super::prepare_encoder(&config, data.len()).unwrap();
    let security = SecurityContext::new(AuthKey::from_seed(42));
    let symbols = encoder
        .encode(object, data)
        .map(|encoded| security.sign_symbol(&encoded.unwrap().into_symbol()))
        .collect();
    let blocks = u16::try_from(data.len().div_ceil(256)).unwrap();
    let per_block = u16::try_from(data.len().min(256).div_ceil(64)).unwrap();
    (
        ObjectParams::new(object, data.len() as u64, 64, blocks, per_block),
        symbols,
    )
}

fn receiver(
    symbols: Vec<AuthenticatedSymbol>,
    metrics: Metrics,
) -> (RaptorQReceiver<Source>, Arc<AtomicUsize>) {
    let polls = Arc::new(AtomicUsize::new(0));
    let receiver = RaptorQReceiverBuilder::new()
        .config(config())
        .source(Source {
            symbols: symbols.into(),
            polls: Arc::clone(&polls),
        })
        .security(SecurityContext::new(AuthKey::from_seed(42)))
        .metrics(metrics)
        .build()
        .unwrap();
    (receiver, polls)
}

fn runtime() -> Runtime {
    RuntimeBuilder::current_thread()
        .enable_platform_reactor(false)
        .blocking_threads(1, 1)
        .build()
        .unwrap()
}

struct HeldWorker {
    release: Option<mpsc::Sender<()>>,
    work: BlockingTaskHandle,
}

impl HeldWorker {
    fn release(&mut self) {
        if let Some(release) = self.release.take() {
            release.send(()).unwrap();
        }
        assert!(self.work.wait_timeout(WAIT));
    }
}

impl Drop for HeldWorker {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        let _ = self.work.wait_timeout(WAIT);
    }
}

fn hold_worker(pool: &BlockingPoolHandle) -> HeldWorker {
    let (started, entered) = mpsc::channel();
    let (release, wait) = mpsc::channel();
    let work = pool
        .try_spawn(move || {
            started.send(()).unwrap();
            wait.recv_timeout(WAIT).unwrap();
        })
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    HeldWorker {
        release: Some(release),
        work,
    }
}

fn await_queued(runtime: &Runtime, pool: &BlockingPoolHandle) {
    runtime.block_on(async {
        let until = Instant::now() + WAIT;
        while pool.pending_count() == 0 {
            assert!(
                Instant::now() < until,
                "decode job must reach the occupied pool"
            );
            crate::runtime::yield_now::yield_now().await;
        }
    });
    assert_eq!(
        pool.pending_count(),
        1,
        "one session admits only one decode job"
    );
}

fn quiescent(runtime: &Runtime) {
    let report = runtime.shutdown_drained(WAIT);
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
}

#[test]
fn queued_decode_pauses_intake_and_survives_dropped_borrowing_wait() {
    bounded(|| {
        let runtime = runtime();
        let pool = runtime.blocking_handle().unwrap();
        let mut held = hold_worker(&pool);
        let owner = runtime.request_cx_with_budget(Budget::INFINITE);
        let driver = runtime.request_cx_with_budget(Budget::INFINITE);
        let data: Vec<u8> = (0..513).map(|n| (n % 251) as u8).collect();
        let (params, symbols) = encoded(&data);
        let mut metrics = Metrics::new();
        let symbols_metric = metrics.counter("raptorq.symbols_received");
        let objects_metric = metrics.counter("raptorq.objects_received");
        let (mut receiver, polls) = receiver(symbols, metrics);
        let mut session = receiver
            .start_receive_object_offloaded(&owner, &params)
            .unwrap();
        runtime.block_on(poll_fn(|task| {
            let mut waiting = std::pin::pin!(session.run());
            assert!(waiting.as_mut().poll(task).is_pending());
            Poll::Ready(())
        }));
        assert_eq!(session.symbols_received(), 4);
        assert_eq!(polls.load(Ordering::SeqCst), 4);
        await_queued(&runtime, &pool);
        let job = session.decode_job.as_ref().unwrap().task_id();
        runtime.block_on(async {
            // This task executes while the solve is waiting for the pool: the
            // sole asynchronous worker remains available for unrelated work.
            let mut heartbeat = driver.spawn(|_| async { 17 }).unwrap();
            assert_eq!(heartbeat.join(&driver).await.unwrap(), 17);
            poll_fn(|task| {
                let mut waiting = std::pin::pin!(session.run());
                assert!(waiting.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
        });
        assert_eq!(session.decode_job.as_ref().unwrap().task_id(), job);
        assert_eq!(pool.pending_count(), 1);
        assert_eq!(
            polls.load(Ordering::SeqCst),
            4,
            "no source overread while solve is pending"
        );
        assert_eq!(symbols_metric.get(), 4);
        assert_eq!(objects_metric.get(), 0);
        held.release();
        let outcome = runtime.block_on(session.run()).unwrap();
        assert_eq!(outcome.data, data);
        assert!(outcome.all_symbols_verified());
        assert_eq!(outcome.symbols_received, 9);
        assert_eq!(
            symbols_metric.get(),
            9,
            "finishing each job does not recount its trigger"
        );
        assert_eq!(objects_metric.get(), 1);
        assert!(session.decode_job.is_none());
        drop(session);
        quiescent(&runtime);
    });
}

#[test]
fn cancel_or_drop_retains_queued_decode_in_the_region_until_pool_retirement() {
    bounded(|| {
        for cancel in [false, true] {
            let runtime = runtime();
            let pool = runtime.blocking_handle().unwrap();
            let mut held = hold_worker(&pool);
            let owner = runtime.request_cx_with_budget(Budget::INFINITE);
            let (params, symbols) = encoded(&vec![3; 513]);
            let (mut receiver, polls) = receiver(symbols, Metrics::new());
            let mut session = Some(
                receiver
                    .start_receive_object_offloaded(&owner, &params)
                    .unwrap(),
            );
            runtime.block_on(poll_fn(|task| {
                let mut waiting = std::pin::pin!(session.as_mut().unwrap().run());
                assert!(waiting.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }));
            await_queued(&runtime, &pool);
            if cancel {
                owner.set_cancel_requested(true);
                let result = runtime.block_on(session.as_mut().unwrap().run());
                assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
                assert!(session.as_ref().unwrap().decode_job.is_none());
                assert!(session.as_ref().unwrap().is_finished());
            } else {
                session = None;
            }
            assert_eq!(polls.load(Ordering::SeqCst), 4);
            let report = runtime.shutdown_drained(Duration::from_millis(20));
            assert_eq!(report.outcome, RootDrainOutcome::TimedOut, "{report:?}");
            assert!(
                report.live_tasks > 0,
                "abandoning a handle cannot detach queued work"
            );
            held.release();
            quiescent(&runtime);
            drop(session);
        }
    });
}

#[test]
fn offloaded_repair_decode_matches_inline_across_multiple_blocks_and_empty_object() {
    bounded(|| {
        for size in [0, 513] {
            let runtime = runtime();
            let owner = runtime.request_cx_with_budget(Budget::INFINITE);
            let data: Vec<u8> = (0..size).map(|n| (n % 251) as u8).collect();
            let (params, symbols) = encoded(&data);
            // Lose the first source symbol of every block, requiring actual
            // repair-row reconstruction instead of the systematic shortcut.
            let surviving: Vec<_> = symbols
                .into_iter()
                .filter(|symbol| symbol.symbol().id().esi() != 0)
                .collect();
            let available_symbols = surviving.len();
            let (mut inline, _) = receiver(surviving.clone(), Metrics::new());
            let expected = inline.receive_object(&Cx::for_testing(), &params).unwrap();
            let (mut receiver, polls) = receiver(surviving, Metrics::new());
            let mut session = receiver
                .start_receive_object_offloaded(&owner, &params)
                .unwrap();
            let actual = runtime.block_on(session.run()).unwrap();
            assert_eq!(actual.data, data);
            assert_eq!(actual.data, expected.data);
            assert!(expected.all_symbols_verified());
            assert!(actual.symbols_received <= available_symbols);
            assert!(actual.all_symbols_verified());
            if size == 0 {
                assert_eq!(polls.load(Ordering::SeqCst), 0);
            }
            drop(session);
            quiescent(&runtime);
        }
    });
}

#[test]
fn offload_refuses_missing_or_forbidden_pool_before_source_intake() {
    bounded(|| {
        let (params, symbols) = encoded(&[7; 64]);
        let (mut receiver, polls) = receiver(symbols.clone(), Metrics::new());
        assert!(
            receiver
                .start_receive_object_offloaded(&Cx::for_testing(), &params)
                .is_err()
        );
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        for forbidden in [false, true] {
            let builder = RuntimeBuilder::current_thread().enable_platform_reactor(false);
            let runtime = if forbidden {
                builder
                    .blocking_threads(1, 1)
                    .blocking_admission_policy(BlockingAdmissionPolicy::Forbidden)
                    .build()
                    .unwrap()
            } else {
                builder.blocking_threads(0, 0).build().unwrap()
            };
            let owner = runtime.request_cx_with_budget(Budget::INFINITE);
            assert!(
                receiver
                    .start_receive_object_offloaded(&owner, &params)
                    .is_err()
            );
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            quiescent(&runtime);
        }
    });
}

#[test]
fn offload_spawn_authorization_failure_never_falls_back_to_inline_decode() {
    bounded(|| {
        let runtime = RuntimeBuilder::current_thread()
            .enable_platform_reactor(false)
            .blocking_threads(1, 1)
            .require_spawn_authorization(AuthKey::from_seed(999))
            .build()
            .unwrap();
        let owner = runtime.request_cx_with_budget(Budget::INFINITE);
        let (params, symbols) = encoded(&[7; 256]);
        let (mut receiver, polls) = receiver(symbols, Metrics::new());
        let mut session = receiver
            .start_receive_object_offloaded(&owner, &params)
            .unwrap();
        let result = runtime.block_on(session.run());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::DispatchFailed);
        assert_eq!(polls.load(Ordering::SeqCst), 4);
        assert!(session.is_finished());
        assert!(session.decode_job.is_none());
        assert_eq!(runtime.blocking_handle().unwrap().pending_count(), 0);
        assert_eq!(
            runtime.block_on(session.run()).unwrap_err().kind(),
            ErrorKind::DispatchFailed
        );
        assert_eq!(polls.load(Ordering::SeqCst), 4);
        drop(session);
        quiescent(&runtime);
    });
}
