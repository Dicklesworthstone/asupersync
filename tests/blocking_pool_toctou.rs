//! Regression test for a `BlockingPool` spawn/shutdown TOCTOU race.

use asupersync::runtime::{BlockingPool, BlockingTaskHandle};
#[cfg(feature = "test-internals")]
use asupersync::{Cx, runtime::spawn_blocking};
#[cfg(feature = "test-internals")]
use futures_lite::future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const RACE_ATTEMPTS: usize = 256;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const HANDLE_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug)]
enum SpawnApi {
    Pool,
    Handle,
}

fn spawn_with_api(
    api: SpawnApi,
    pool: &BlockingPool,
    executions: Arc<AtomicUsize>,
) -> BlockingTaskHandle {
    match api {
        SpawnApi::Pool => pool.spawn(move || {
            executions.fetch_add(1, Ordering::AcqRel);
        }),
        SpawnApi::Handle => pool.handle().spawn(move || {
            executions.fetch_add(1, Ordering::AcqRel);
        }),
    }
}

fn assert_race_outcome(
    api: SpawnApi,
    attempt: usize,
    handle: &BlockingTaskHandle,
    executions: usize,
) -> Result<(), String> {
    match (handle.is_cancelled(), executions) {
        (true, 0) | (false, 1) => Ok(()),
        (true, count) => Err(format!(
            "{api:?} attempt {attempt}: rejected spawn still executed {count} time(s)",
        )),
        (false, count) => Err(format!(
            "{api:?} attempt {attempt}: accepted spawn executed {count} time(s), expected exactly one",
        )),
    }
}

fn run_spawn_shutdown_race(api: SpawnApi) -> Result<(), String> {
    for attempt in 0..RACE_ATTEMPTS {
        let pool = Arc::new(BlockingPool::new(1, 1));
        let executions = Arc::new(AtomicUsize::new(0));

        let executions_for_task = Arc::clone(&executions);
        let pool_for_spawn = Arc::clone(&pool);
        let pool_for_shutdown = Arc::clone(&pool);

        let spawn_thread =
            std::thread::spawn(move || spawn_with_api(api, &pool_for_spawn, executions_for_task));

        let shutdown_thread = std::thread::spawn(move || {
            pool_for_shutdown.shutdown();
        });

        let handle = match spawn_thread.join() {
            Ok(handle) => handle,
            Err(_) => return Err(format!("{api:?} attempt {attempt}: spawn thread panicked")),
        };
        if shutdown_thread.join().is_err() {
            return Err(format!(
                "{api:?} attempt {attempt}: shutdown thread panicked",
            ));
        }

        if !pool.shutdown_and_wait(DRAIN_TIMEOUT) {
            return Err(format!(
                "{api:?} attempt {attempt}: pool did not drain after shutdown",
            ));
        }
        if !handle.wait_timeout(HANDLE_TIMEOUT) {
            return Err(format!(
                "{api:?} attempt {attempt}: task handle was never completed",
            ));
        }
        if pool.pending_count() != 0 {
            return Err(format!(
                "{api:?} attempt {attempt}: shutdown left {} queued blocking task(s)",
                pool.pending_count(),
            ));
        }
        if pool.active_threads() != 0 {
            return Err(format!(
                "{api:?} attempt {attempt}: shutdown left {} active blocking worker(s)",
                pool.active_threads(),
            ));
        }

        assert_race_outcome(api, attempt, &handle, executions.load(Ordering::Acquire))?;
    }

    Ok(())
}

#[test]
fn pool_spawn_shutdown_race_completes_or_cancels() -> Result<(), String> {
    run_spawn_shutdown_race(SpawnApi::Pool)
}

#[test]
fn handle_spawn_shutdown_race_completes_or_cancels() -> Result<(), String> {
    run_spawn_shutdown_race(SpawnApi::Handle)
}

#[test]
fn blocking_helper_boundary_census_requires_classification() {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    fn visit(root: &Path, directory: &Path, found: &mut BTreeMap<(PathBuf, String), usize>) {
        for entry in std::fs::read_dir(directory).expect("read runtime source boundary") {
            let entry = entry.expect("source entry");
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                visit(root, &path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = std::fs::read_to_string(&path).expect("read Rust boundary source");
                for line in source.lines().map(str::trim_start) {
                    let declaration = [
                        "pub async fn ",
                        "pub fn ",
                        "pub(crate) async fn ",
                        "pub(crate) fn ",
                    ]
                    .into_iter()
                    .find_map(|prefix| line.strip_prefix(prefix));
                    let Some(declaration) = declaration else {
                        continue;
                    };
                    let name = declaration.split(['<', '(']).next().unwrap();
                    if name.starts_with("spawn_blocking") {
                        let relative = path.strip_prefix(root).unwrap().to_path_buf();
                        *found.entry((relative, name.to_owned())).or_default() += 1;
                    }
                }
            }
        }
    }

    // Free helpers preserve the assigned placement independently of SPAWN.
    // Cx methods admit region-owned tasks through a SPAWN-checked gateway.
    // Runtime/RuntimeHandle methods use explicitly held pool ownership.
    // The two private free-helper dispatchers preserve pool/thread fallbacks.
    let expected = [
        ("runtime/spawn_blocking.rs", "spawn_blocking", 1),
        ("runtime/spawn_blocking.rs", "spawn_blocking_io", 1),
        ("runtime/spawn_blocking.rs", "spawn_blocking_on_pool", 1),
        ("runtime/spawn_blocking.rs", "spawn_blocking_on_thread", 1),
        ("cx/cx.rs", "spawn_blocking", 1),
        ("cx/cx.rs", "spawn_blocking_in", 1),
        ("runtime/builder.rs", "spawn_blocking", 2),
        ("runtime/builder.rs", "spawn_blocking_on_cohort", 2),
    ]
    .into_iter()
    .map(|(path, name, count)| ((PathBuf::from(path), name.to_owned()), count))
    .collect::<BTreeMap<_, _>>();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = BTreeMap::new();
    visit(&root, &root.join("runtime"), &mut found);
    visit(&root, &root.join("cx"), &mut found);
    assert_eq!(
        found, expected,
        "classify new blocking helpers before admitting the release lane"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_restricted_context_preserves_queued_blocking_io_and_cleanup() {
    use asupersync::runtime::{RuntimeBuilder, SpawnError, spawn_blocking, spawn_blocking_io};
    use asupersync::{Cx, cx::cap};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::mpsc;
    use std::task::{Context, Poll, Waker};

    #[derive(Clone, Copy, Debug)]
    enum Operation {
        Value,
        IoValue,
        IoError,
    }

    for operation in [Operation::Value, Operation::IoValue, Operation::IoError] {
        let pool = BlockingPool::new(1, 1);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let blocker = pool.spawn(move || {
            started_tx.send(std::thread::current().id()).unwrap();
            // Dropping the sender also releases the worker if an assertion
            // unwinds before the normal release below.
            let _ = release_rx.recv();
        });
        let pool_thread = started_rx
            .recv_timeout(DRAIN_TIMEOUT)
            .expect("the caller-owned worker must be occupied before submission");
        assert_eq!(pool.busy_threads(), 1);

        let executed = Arc::new(AtomicUsize::new(0));
        let executed_in_worker = Arc::clone(&executed);
        let (observed_tx, observed_rx) = mpsc::channel();
        let work = move || {
            executed_in_worker.fetch_add(1, Ordering::SeqCst);
            observed_tx
                .send((std::thread::current().id(), Cx::is_active()))
                .unwrap();
            42_u32
        };
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let caller_thread = std::thread::current().id();
        let (first_pending, queued, before_execution, result) = runtime.block_on(async {
            let parent = Cx::current().expect("native caller context");
            let restricted = parent
                .clone()
                .with_blocking_pool_handle(Some(pool.handle()))
                .restrict::<cap::None>();
            let mut future: Pin<Box<dyn Future<Output = std::io::Result<u32>>>> = match operation {
                Operation::Value => Box::pin(async move { Ok(spawn_blocking(work).await) }),
                Operation::IoValue => Box::pin(spawn_blocking_io(move || Ok(work()))),
                Operation::IoError => Box::pin(spawn_blocking_io(move || {
                    let _ = work();
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "caller-owned I/O refusal",
                    ))
                })),
            };
            let first = {
                let _guard = restricted.clone().set_current_restricted();
                let ambient = Cx::current().expect("restricted caller context");
                assert!(!ambient.capabilities().spawn);
                assert!(ambient.blocking_pool_handle().is_none());
                assert!(matches!(
                    ambient.spawn(|_| async {}),
                    Err(SpawnError::RuntimeUnavailable)
                ));
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
            };
            let first_pending = first.is_pending();
            let queued = pool.pending_count();
            let before_execution = executed.load(Ordering::SeqCst);
            // Record the formerly failing state before releasing capacity.
            // Assert it after cleanup so old-code failure cannot park a worker.
            release_tx.send(()).expect("release the occupied worker");
            let result = match first {
                Poll::Ready(result) => result,
                Poll::Pending => {
                    std::future::poll_fn(|task| {
                        let _guard = restricted.clone().set_current_restricted();
                        future.as_mut().poll(task)
                    })
                    .await
                }
            };
            let restored = Cx::current().expect("caller context restored after every poll");
            assert_eq!(restored.task_id(), parent.task_id());
            assert_eq!(restored.region_id(), parent.region_id());
            assert_eq!(restored.capabilities(), parent.capabilities());
            (first_pending, queued, before_execution, result)
        });

        assert!(blocker.wait_timeout(DRAIN_TIMEOUT));
        assert!(pool.shutdown_and_wait(DRAIN_TIMEOUT));
        assert_eq!(pool.pending_count(), 0);
        assert_eq!(pool.active_threads(), 0);
        assert!(
            first_pending,
            "{operation:?}: the occupied pool must queue work"
        );
        assert_eq!(queued, 1, "{operation:?}: observe the owned queue entry");
        assert_eq!(before_execution, 0, "{operation:?}: no inline execution");
        assert_eq!(executed.load(Ordering::SeqCst), 1);
        let (execution_thread, ambient_active) = observed_rx.try_recv().unwrap();
        assert_eq!(
            execution_thread, pool_thread,
            "{operation:?}: reuse the assigned pool"
        );
        assert_ne!(execution_thread, caller_thread);
        assert!(
            !ambient_active,
            "workers must not acquire ambient authority"
        );
        match operation {
            Operation::Value | Operation::IoValue => assert_eq!(result.unwrap(), 42),
            Operation::IoError => {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                assert_eq!(error.to_string(), "caller-owned I/O refusal");
            }
        }
    }
}

#[cfg(feature = "test-internals")]
#[test]
fn embedder_context_routes_spawn_blocking_to_caller_owned_pool() {
    let pool = BlockingPool::new(1, 1);
    let cx = Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));

    let thread_name = {
        let _guard = Cx::set_current(Some(cx));
        future::block_on(spawn_blocking(|| {
            std::thread::current()
                .name()
                .unwrap_or("unnamed")
                .to_owned()
        }))
    };

    assert!(
        thread_name.contains("-blocking-"),
        "spawn_blocking bypassed the caller-owned pool: {thread_name}"
    );
    assert!(pool.shutdown_and_wait(DRAIN_TIMEOUT));
}
