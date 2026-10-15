//! Native ownership and restart journeys for the opt-in execution adapter.

use super::*;
use crate::channel::oneshot;
use crate::cx::ChildRegionSpec;
use crate::distributed::SchemaDescriptor;
use crate::remote::{
    ComputationName, IdempotencyKey, NodeId, RemoteInput, RemotePeerAdmissionPolicy,
    RemoteProtocolVersion, RemoteTaskId, SpawnRequest,
};
use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
use crate::security::AuthKey;
use crate::sync::Notify;
use crate::types::{Budget, CancelReason};
use std::future::poll_fn;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex as StdMutex};
use std::task::Poll;
use std::time::Duration;

const NAME: &str = "durable-native";
const PEER: &str = "authenticated-peer";
const VERSION: [u8; 32] = [7; 32];
const INPUT: &[u8] = b"one application effect";

struct Input;
struct Output;
struct OtherInput;

impl HasSchema for Input {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("durable-native.input.v1")
    }
}

impl HasSchema for Output {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("durable-native.output.v1")
    }
}

impl HasSchema for OtherInput {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("durable-native.other-input.v1")
    }
}

fn limits() -> DurableRemoteLimits {
    DurableRemoteLimits {
        max_entries: 8,
        max_peer_entries: 4,
        max_input_bytes: 128,
        max_outcome_bytes: 512,
        max_retained_bytes: 4096,
        max_journal_bytes: 64 * 1024,
        retention_ms: 10_000,
    }
}

struct JournalFile {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

// File provisioning is test-only even when the source audit reads this module
// without seeing its parent's `#[cfg(test)] mod tests` declaration.
#[cfg(test)]
impl JournalFile {
    fn create() -> (Self, DurableRemoteJournal) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let journal = DurableRemoteJournal::create::<Input, Output>(
            file, NAME, VERSION, AuthKey::from_seed(99), limits(),
        )
        .unwrap();
        (Self { _directory: directory, path }, journal)
    }

    fn reopen(&self) -> Result<DurableRemoteJournal, DurableRemoteError> {
        let file = std::fs::OpenOptions::new().read(true).write(true).open(&self.path).unwrap();
        DurableRemoteJournal::open::<Input, Output>(
            file, NAME, VERSION, AuthKey::from_seed(99), limits(),
        )
    }
}

fn run<F: Future>(runtime: &Runtime, future: F) -> F::Output {
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        crate::time::timeout(cx.now(), Duration::from_secs(10), future)
            .await
            .expect("durable adapter workflow must terminate and retire its owners")
    })
}

fn native_runtime(workers: usize, blocking: bool) -> Runtime {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers)
    };
    builder
        .blocking_threads(usize::from(blocking), usize::from(blocking))
        .build()
        .unwrap()
}

fn drained(runtime: &Runtime) {
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.live_regions, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
    assert_eq!(report.queued_finalizers, 0);
    assert!(!report.has_pending_obligation_posts);
}

fn request(cx: &Cx, key: u128) -> SpawnRequest {
    SpawnRequest {
        remote_task_id: RemoteTaskId::next(),
        computation: ComputationName::new(NAME),
        input: RemoteInput::new(INPUT.to_vec()),
        lease: Duration::from_secs(20),
        idempotency_key: IdempotencyKey::from_raw(key),
        budget: None,
        origin_node: NodeId::new("untrusted-origin-metadata"),
        origin_region: cx.region_id(),
        origin_task: cx.task_id(),
    }
}

// This module is below remote's admission boundary. Only the fixture constructs
// the private invocation directly; the registered journey uses a real session.
fn invocation(cx: &Cx, key: u128) -> RemoteComputationInvocation {
    RemoteComputationInvocation {
        peer_node: NodeId::new(PEER),
        request: request(cx, key),
    }
}

fn records(owner: &DurableRemoteComputation) -> u64 {
    owner.journal.lock().as_ref().expect("journal returned to its owner").records()
}

fn success(outcome: RemoteOutcome, expected: &[u8]) {
    match outcome {
        RemoteOutcome::Success(bytes) => assert_eq!(bytes, expected),
        other => panic!("expected exact durable success, got {other:?}"),
    }
}

#[derive(Default)]
struct WorkerGate {
    entered: AtomicBool,
    changed: Notify,
    released: StdMutex<bool>,
    release_changed: Condvar,
}

impl WorkerGate {
    fn block(&self) {
        self.entered.store(true, Ordering::Release);
        self.changed.notify_waiters();
        let released = self.released.lock().unwrap();
        let (released, _) = self
            .release_changed
            .wait_timeout_while(released, Duration::from_secs(15), |released| !*released)
            .unwrap();
        assert!(*released, "test must release the actual blocking worker");
    }

    fn release(&self) {
        *self.released.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        self.release_changed.notify_all();
    }

    async fn entered(&self) {
        self.changed.wait_until(|| self.entered.load(Ordering::Acquire)).await;
    }
}

struct ReleaseOnDrop(Arc<WorkerGate>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct Retired(Arc<AtomicUsize>);

impl Drop for Retired {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn registration_rejects_mismatched_schema_and_duplicate_without_replacing_handler() {
    let (_file, journal) = JournalFile::create();
    let fingerprint = journal.schema_fingerprint();
    let owner = Arc::new(DurableRemoteComputation::new(journal, || 1000));
    let mut registry = RemoteComputationRegistry::new();
    let wrong = owner.register::<OtherInput, Output, _, _>(&mut registry, |_, _| async {
        RemoteOutcome::Success(Vec::new())
    });
    assert!(matches!(wrong, Err(DurableRemoteError::Configuration)));
    assert!(registry.is_empty());
    owner.register::<Input, Output, _, _>(&mut registry, |_, _| async {
        RemoteOutcome::Success(INPUT.to_vec())
    }).unwrap();
    assert_eq!(registry.schema_registry().fingerprint(), fingerprint);
    let duplicate = owner.register::<Input, Output, _, _>(&mut registry, |_, _| async {
        panic!("duplicate registration must not replace the first handler")
    });
    assert!(matches!(duplicate, Err(DurableRemoteError::Configuration)));
    assert_eq!(registry.len(), 1);
    assert_eq!(records(&owner), 0, "registration performs no reservation");
    assert!(!owner.in_flight());

    let runtime = native_runtime(1, true);
    run(&runtime, async {
        let cx = Cx::current().unwrap();
        let mut policy = RemotePeerAdmissionPolicy::new(
            RemoteProtocolVersion::V3, registry.schema_registry().clone(),
        );
        policy.grant_peer(NodeId::new(PEER), [NAME]).unwrap();
        let session = policy.admit(&policy.hello_for(NodeId::new(PEER))).unwrap();
        success(registry.dispatch(&cx, &session, request(&cx, 1)).await.unwrap(), INPUT);
    });
    assert_eq!(records(&owner), 2);
    drained(&runtime);
}

#[test]
fn missing_blocking_pool_refuses_before_reservation_or_handler() {
        for workers in [1, 2] {
            let (_file, journal) = JournalFile::create();
            let owner = Arc::new(DurableRemoteComputation::new(journal, || 1000));
            let runtime = native_runtime(workers, false);
            run(&runtime, async {
                let cx = Cx::current().unwrap();
                assert!(cx.blocking_pool_handle().is_none());
                let result = owner.call(&cx, invocation(&cx, 2), |_, _| async {
                    panic!("a missing blocking capability cannot fall back to handler execution")
                }).await;
                assert!(matches!(result, Err(DurableRemoteError::Unavailable)));
                assert!(!owner.in_flight());
                assert_eq!(owner.journal_status(), Some(DurableRemoteJournalStatus::Writable));
                assert_eq!(records(&owner), 0);
            });
            drained(&runtime);
        }
}

#[test]
fn registered_native_execution_persists_before_return_and_replays_after_restart() {
        for workers in [1, 2] {
            let (file, journal) = JournalFile::create();
            let owner = Arc::new(DurableRemoteComputation::new(journal, || 1000));
            let calls = Arc::new(AtomicUsize::new(0));
            let (release, release_rx) = oneshot::channel::<()>();
            let release_rx = Arc::new(Mutex::new(Some(release_rx)));
            let (parked, mut parked_rx) = oneshot::channel();
            let parked = Arc::new(Mutex::new(Some(parked)));
            let mut registry = RemoteComputationRegistry::new();
            let handler_calls = Arc::clone(&calls);
            owner.register::<Input, Output, _, _>(&mut registry, move |body, invocation| {
                handler_calls.fetch_add(1, Ordering::SeqCst);
                let mut release = release_rx.lock().take().expect("one execution");
                let mut parked = parked.lock().take();
                async move {
                    assert_eq!(invocation.peer_node(), &NodeId::new(PEER));
                    assert_ne!(invocation.peer_node(), &invocation.request().origin_node);
                    poll_fn(|task| {
                        let poll = release.poll_recv_uninterruptible(task);
                        if poll.is_pending() && let Some(parked) = parked.take() {
                            parked.send_blocking(body.clone()).unwrap();
                        }
                        poll
                    }).await.unwrap();
                    RemoteOutcome::Success(invocation.into_request().input.into_data())
                }
            }).unwrap();
            let runtime = native_runtime(workers, true);
            run(&runtime, async {
                let cx = Cx::current().unwrap();
                let mut policy = RemotePeerAdmissionPolicy::new(
                    RemoteProtocolVersion::V3, registry.schema_registry().clone(),
                );
                policy.grant_peer(NodeId::new(PEER), [NAME]).unwrap();
                let session = policy.admit(&policy.hello_for(NodeId::new(PEER))).unwrap();
                let task_registry = registry.clone();
                let task_session = session.clone();
                let first = request(&cx, 3);
                let mut running = cx.spawn(move |body| async move {
                    task_registry.dispatch(&body, &task_session, first).await
                }).unwrap();
                let body: Cx = parked_rx.recv(&cx).await.unwrap();
                assert!(!body.is_cancel_requested());
                assert!(!running.is_finished());
                assert!(owner.in_flight());
                assert_eq!(owner.journal_status(), None);
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                let busy = owner.call(&cx, invocation(&cx, 4), |_, _| async {
                    panic!("the one journal slot cannot admit concurrent effects")
                }).await;
                assert!(matches!(busy, Err(DurableRemoteError::Busy)));
                release.send(&cx, ()).unwrap();
                success(running.join(&cx).await.unwrap().unwrap(), INPUT);
                assert!(!owner.in_flight());
                assert_eq!(records(&owner), 2, "reservation and terminal precede the receipt");

                let mut retry = request(&cx, 3);
                retry.origin_node = NodeId::new("changed-untrusted-origin");
                retry.lease = Duration::from_secs(1);
                retry.budget = Some(Budget::INFINITE.with_poll_quota(1));
                success(registry.dispatch(&cx, &session, retry).await.unwrap(), INPUT);
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert_eq!(records(&owner), 2, "an exact retry writes no second reservation");
            });
            drop(registry);
            drop(owner);
            drained(&runtime);

            let journal = file.reopen().unwrap();
            assert_eq!(journal.records(), 2);
            let owner = Arc::new(DurableRemoteComputation::new(journal, || 1001));
            let restarted = native_runtime(workers, true);
            run(&restarted, async {
                let cx = Cx::current().unwrap();
                success(owner.call(&cx, invocation(&cx, 3), |_, _| async {
                    panic!("a recovered terminal result must not execute the handler")
                }).await.unwrap(), INPUT);
                assert_eq!(records(&owner), 2);
            });
            drained(&restarted);
        }
}

#[test]
#[allow(clippy::async_yields_async)]
fn queued_admission_drop_retains_journal_and_file_lock_until_worker_retirement() {
        for workers in [1, 2] {
            let (file, journal) = JournalFile::create();
            let header_bytes = journal.committed_bytes();
            let clocks = Arc::new(AtomicUsize::new(0));
            let clock_calls = Arc::clone(&clocks);
            let owner = Arc::new(DurableRemoteComputation::new(journal, move || {
                clock_calls.fetch_add(1, Ordering::SeqCst);
                1000
            }));
            let retained = Arc::downgrade(&owner);
            let runtime = native_runtime(workers, true);
            let pool = runtime.blocking_handle().unwrap();
            let gate = Arc::new(WorkerGate::default());
            let _release_on_unwind = ReleaseOnDrop(Arc::clone(&gate));
            let worker_gate = Arc::clone(&gate);
            let blocker = pool.spawn(move || worker_gate.block());
            let closing = run(&runtime, async {
                let cx = Cx::current().unwrap();
                gate.entered().await;
                let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                let mut call = Box::pin(owner.call(region.cx(), invocation(region.cx(), 5), |_, _| async {
                    panic!("cancelled queued admission must never invoke the handler")
                }));
                poll_fn(|task| {
                    assert!(call.as_mut().poll(task).is_pending(), "the disk worker is occupied");
                    if pool.pending_count() == 1 {
                        Poll::Ready(())
                    } else {
                        task.waker().wake_by_ref();
                        Poll::Pending
                    }
                }).await;
                drop(call);
                assert!(owner.in_flight());
                assert_eq!(owner.journal_status(), None);
                drop(owner);
                let mut closing = Box::pin(region.close());
                poll_fn(|task| {
                    assert!(closing.as_mut().poll(task).is_pending(),
                        "region close must retain the cancelled pool envelope");
                    Poll::Ready(())
                }).await;
                closing
            });
            assert!(retained.upgrade().expect("only queued work owns this Arc").in_flight());
            assert!(matches!(file.reopen(), Err(DurableRemoteError::Locked)));
            assert_eq!(std::fs::metadata(&file.path).unwrap().len(), header_bytes);
            assert_eq!(clocks.load(Ordering::SeqCst), 0);
            assert_eq!(pool.pending_count(), 1);
            assert!(!runtime.task_inspector(Default::default()).list_active_tasks().is_empty());

            gate.release();
            assert!(blocker.wait_timeout(Duration::from_secs(5)));
            run(&runtime, closing).unwrap();
            assert!(retained.upgrade().is_none(), "retired captures release the final file owner");
            assert_eq!(clocks.load(Ordering::SeqCst), 0, "the queued claim was fenced");
            assert_eq!(file.reopen().unwrap().records(), 0);
            drained(&runtime);
        }
}

#[test]
fn dropping_a_reserved_pending_handler_fences_reexecution_across_restart_and_ttl() {
        for workers in [1, 2] {
            let (file, journal) = JournalFile::create();
            let now = Arc::new(AtomicU64::new(1000));
            let clock = Arc::clone(&now);
            let owner = Arc::new(DurableRemoteComputation::new(journal, move || clock.load(Ordering::Acquire)));
            let effects = Arc::new(AtomicUsize::new(0));
            let retired = Arc::new(AtomicUsize::new(0));
            let runtime = native_runtime(workers, true);
            run(&runtime, async {
                let cx = Cx::current().unwrap();
                let (parked, mut parked_rx) = oneshot::channel();
                let handler_effects = Arc::clone(&effects);
                let handler_retired = Arc::clone(&retired);
                let mut call = Box::pin(owner.call(&cx, invocation(&cx, 6), move |_, _| async move {
                    let _retired = Retired(handler_retired);
                    handler_effects.fetch_add(1, Ordering::SeqCst);
                    let mut parked = Some(parked);
                    let mut pending = std::pin::pin!(std::future::pending::<RemoteOutcome>());
                    poll_fn(|task| {
                        let poll = pending.as_mut().poll(task);
                        if poll.is_pending() && let Some(parked) = parked.take() {
                            parked.send_blocking(()).unwrap();
                        }
                        poll
                    }).await
                }));
                poll_fn(|task| {
                    assert!(call.as_mut().poll(task).is_pending());
                    parked_rx.poll_recv_uninterruptible(task)
                }).await.unwrap();
                assert_eq!(effects.load(Ordering::SeqCst), 1);
                assert_eq!(retired.load(Ordering::SeqCst), 0);
                drop(call);
                assert_eq!(retired.load(Ordering::SeqCst), 1, "dropping the call drops its actual handler");
                assert!(!owner.in_flight());
                assert_eq!(records(&owner), 1, "the effect began after a durable reservation");
                now.store(1_000_000, Ordering::Release);
                let retry = owner.call(&cx, invocation(&cx, 6), |_, _| async {
                    panic!("uncertain effects never receive automatic execution permission")
                }).await;
                assert!(matches!(retry, Err(DurableRemoteError::InDoubt)));
                assert_eq!(records(&owner), 1);
            });
            drop(owner);
            drained(&runtime);
            let journal = file.reopen().unwrap();
            assert_eq!(journal.records(), 1);
            let owner = Arc::new(DurableRemoteComputation::new(journal, || 2_000_000));
            let restarted = native_runtime(workers, true);
            run(&restarted, async {
                let cx = Cx::current().unwrap();
                let retry = owner.call(&cx, invocation(&cx, 6), |_, _| async {
                    panic!("restart and many terminal TTLs do not clear an in-doubt fence")
                }).await;
                assert!(matches!(retry, Err(DurableRemoteError::InDoubt)));
                assert_eq!(records(&owner), 1);
                assert_eq!(effects.load(Ordering::SeqCst), 1);
                assert_eq!(retired.load(Ordering::SeqCst), 1);
            });
            drained(&restarted);
        }
}

#[test]
fn real_spawned_task_preserves_durable_completion_and_replay_after_late_cancellation() {
        for workers in [1, 2] {
            for replay in [false, true] {
                let (file, mut journal) = JournalFile::create();
                if replay {
                    let reservation = match journal.admit(&NodeId::new(PEER), IdempotencyKey::from_raw(7), INPUT, 1000).unwrap() {
                        DurableRemoteAdmission::Execute(reservation) => reservation,
                        DurableRemoteAdmission::Replay(_) => panic!("fresh journal has no terminal"),
                    };
                    journal.complete(reservation, RemoteOutcome::Success(INPUT.to_vec()), 1000).unwrap();
                }
                let gate = Arc::new(WorkerGate::default());
                let clock_gate = Arc::clone(&gate);
                let clocks = AtomicUsize::new(0);
                let owner = Arc::new(DurableRemoteComputation::new(journal, move || {
                    let call = clocks.fetch_add(1, Ordering::SeqCst);
                    // Replay blocks its admission read; a fresh execution
                    // blocks the terminal write after the handler returned.
                    if call == usize::from(!replay) {
                        clock_gate.block();
                    }
                    1000
                }));
                let effects = Arc::new(AtomicUsize::new(0));
                let runtime = native_runtime(workers, true);
                let _release_on_unwind = ReleaseOnDrop(Arc::clone(&gate));
                run(&runtime, async {
                    let cx = Cx::current().unwrap();
                    let task_owner = Arc::clone(&owner);
                    let task_gate = Arc::clone(&gate);
                    let handler_effects = Arc::clone(&effects);
                    let (parked, mut parked_rx) = oneshot::channel();
                    let mut task = cx.spawn(move |body| async move {
                        let mut call = Box::pin(task_owner.call(&body, invocation(&body, 7), move |_, request| async move {
                            handler_effects.fetch_add(1, Ordering::SeqCst);
                            RemoteOutcome::Success(request.into_request().input.into_data())
                        }));
                        let mut entered = Box::pin(task_gate.entered());
                        let mut parked = Some(parked);
                        poll_fn(|task| {
                            let poll = call.as_mut().poll(task);
                            if poll.is_pending() && parked.is_some() && entered.as_mut().poll(task).is_ready() {
                                parked.take().unwrap().send_blocking(body.clone()).unwrap();
                            }
                            // Do not acknowledge cancellation here: this
                            // witness must test the adapter's receipt boundary.
                            poll
                        }).await
                    }).unwrap();
                    let body: Cx = parked_rx.recv(&cx).await.unwrap();
                    assert!(!task.is_finished());
                    assert!(owner.in_flight());
                    assert_eq!(effects.load(Ordering::SeqCst), usize::from(!replay));
                    task.abort_with_reason(CancelReason::user("late durable receipt cancellation"));
                    // Abort publication may cross the scheduler mailbox.
                    // This observer waits for visibility without acknowledging
                    // the target task's cancellation on the adapter's behalf.
                    body.cancelled().await;
                    assert!(body.is_cancel_requested());
                    let mut joining = Box::pin(task.join(&cx));
                    poll_fn(|task| {
                        assert!(joining.as_mut().poll(task).is_pending(), "the actual disk job has not retired");
                        Poll::Ready(())
                    }).await;
                    gate.release();
                    success(joining.await.expect("task-level cancellation must preserve its durable receipt").unwrap(), INPUT);
                    assert!(!owner.in_flight());
                    assert_eq!(records(&owner), 2);
                });
                drop(owner);
                drained(&runtime);
                let mut journal = file.reopen().unwrap();
                assert_eq!(journal.records(), 2);
                match journal.admit(&NodeId::new(PEER), IdempotencyKey::from_raw(7), INPUT, 1001).unwrap() {
                    DurableRemoteAdmission::Replay(outcome) => success(outcome, INPUT),
                    DurableRemoteAdmission::Execute(_) => panic!("a published receipt must survive reopening"),
                }
                assert_eq!(effects.load(Ordering::SeqCst), usize::from(!replay));
            }
        }
}
