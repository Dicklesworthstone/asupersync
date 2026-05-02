#![no_main]

use arbitrary::Arbitrary;
use asupersync::{
    cx::Cx,
    sync::{AsyncResourceFactory, GenericPool, Pool, PoolConfig, PooledResource},
};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::HashSet,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Barrier, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

const MAX_WORKERS: usize = 8;
const MAX_ROUNDS: usize = 8;
const MAX_DELAY_MICROS: u64 = 128;
const MAX_YIELDS: u8 = 8;

#[derive(Debug, Arbitrary)]
struct PoolAcquireReleaseCase {
    workers: Vec<WorkerPlan>,
}

#[derive(Debug, Clone, Arbitrary)]
struct WorkerPlan {
    rounds: u8,
    pre_delay_micros: u16,
    hold_delay_micros: u16,
    post_delay_micros: u16,
    yields_before_release: u8,
    release_mode: ReleaseMode,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum ReleaseMode {
    Drop,
    ExplicitReturn,
    MarkBrokenThenDrop,
    Discard,
}

#[derive(Debug)]
struct MockResource {
    id: usize,
    touches: usize,
}

#[derive(Debug, Clone, Default)]
struct MockFactory {
    created: Arc<AtomicUsize>,
}

#[derive(Debug, Default)]
struct ResourceTracker {
    live: StdMutex<HashSet<usize>>,
    acquired: AtomicUsize,
    released: AtomicUsize,
    max_live: AtomicUsize,
}

fuzz_target!(|case: PoolAcquireReleaseCase| {
    let mut workers: Vec<_> = case.workers.into_iter().take(MAX_WORKERS).collect();
    if workers.is_empty() {
        workers.push(WorkerPlan {
            rounds: 1,
            pre_delay_micros: 0,
            hold_delay_micros: 1,
            post_delay_micros: 0,
            yields_before_release: 1,
            release_mode: ReleaseMode::ExplicitReturn,
        });
    }

    drive_pool_acquire_release(workers);
});

fn drive_pool_acquire_release(workers: Vec<WorkerPlan>) {
    let factory = MockFactory::default();
    let config = PoolConfig::default()
        .min_size(0)
        .max_size(workers.len())
        .acquire_timeout(Duration::from_millis(20));
    let pool = Arc::new(GenericPool::new(factory.clone(), config));
    let tracker = Arc::new(ResourceTracker::default());
    let start = Arc::new(Barrier::new(workers.len() + 1));
    let mut handles = Vec::with_capacity(workers.len());

    for (worker_index, plan) in workers.into_iter().enumerate() {
        let pool = Arc::clone(&pool);
        let tracker = Arc::clone(&tracker);
        let start = Arc::clone(&start);

        handles.push(thread::spawn(move || {
            start.wait();
            run_worker_plan(worker_index, plan, pool, tracker);
        }));
    }

    start.wait();

    for (worker_index, handle) in handles.into_iter().enumerate() {
        handle
            .join()
            .unwrap_or_else(|_| panic!("pool worker thread {worker_index} panicked"));
    }

    let stats = pool.stats();
    tracker.assert_balanced();

    assert_eq!(stats.active, 0, "all pooled resources must be released");
    assert_eq!(
        stats.waiters, 0,
        "joined workers must not leave pool waiters"
    );
    assert_eq!(
        stats.active + stats.idle,
        stats.total,
        "pool total must be exactly active + idle after returns are drained"
    );
    assert!(
        stats.total <= stats.max_size,
        "pool total exceeded configured max size: {stats:?}"
    );
    assert!(
        tracker.created_count(&factory) >= stats.total,
        "stats reported resources that the factory never created"
    );
}

fn run_worker_plan(
    worker_index: usize,
    plan: WorkerPlan,
    pool: Arc<GenericPool<MockResource, MockFactory>>,
    tracker: Arc<ResourceTracker>,
) {
    let cx = Cx::for_testing();
    let rounds = usize::from(plan.rounds).min(MAX_ROUNDS).max(1);

    for round in 0..rounds {
        let salt = worker_index
            .wrapping_mul(131)
            .wrapping_add(round.wrapping_mul(17));

        fuzz_delay(plan.pre_delay_micros, salt);
        let resource = futures_executor::block_on(pool.acquire(&cx))
            .expect("pool acquire should succeed while max_size covers active workers");
        tracker.record_acquire(resource.id);
        fuzz_delay(plan.hold_delay_micros, salt.wrapping_add(31));
        hold_and_release(
            resource,
            &tracker,
            plan.release_mode,
            plan.yields_before_release,
        );
        fuzz_delay(plan.post_delay_micros, salt.wrapping_add(67));
    }
}

fn hold_and_release(
    mut resource: PooledResource<MockResource>,
    tracker: &ResourceTracker,
    release_mode: ReleaseMode,
    yields_before_release: u8,
) {
    let resource_id = resource.id;
    resource.touches = resource.touches.wrapping_add(1);

    for _ in 0..yields_before_release.min(MAX_YIELDS) {
        thread::yield_now();
    }

    tracker.record_release(resource_id);
    match release_mode {
        ReleaseMode::Drop => drop(resource),
        ReleaseMode::ExplicitReturn => resource.return_to_pool(),
        ReleaseMode::MarkBrokenThenDrop => {
            resource.mark_broken();
            drop(resource);
        }
        ReleaseMode::Discard => resource.discard(),
    }
}

fn fuzz_delay(raw_micros: u16, salt: usize) {
    let micros =
        (u64::from(raw_micros) ^ (salt as u64).wrapping_mul(0x9e37_79b9)) % (MAX_DELAY_MICROS + 1);
    if micros == 0 {
        thread::yield_now();
    } else {
        thread::sleep(Duration::from_micros(micros));
    }
}

impl AsyncResourceFactory for MockFactory {
    type Resource = MockResource;
    type Error = io::Error;

    fn create(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Resource, Self::Error>> + Send + '_>> {
        let id = self.created.fetch_add(1, Ordering::AcqRel);
        Box::pin(async move { Ok(MockResource { id, touches: 0 }) })
    }
}

impl ResourceTracker {
    fn record_acquire(&self, resource_id: usize) {
        let mut live = self
            .live
            .lock()
            .expect("resource tracker mutex should not poison");
        assert!(
            live.insert(resource_id),
            "resource {resource_id} was delivered to multiple workers concurrently"
        );
        self.acquired.fetch_add(1, Ordering::SeqCst);
        self.max_live.fetch_max(live.len(), Ordering::SeqCst);
    }

    fn record_release(&self, resource_id: usize) {
        let mut live = self
            .live
            .lock()
            .expect("resource tracker mutex should not poison");
        assert!(
            live.remove(&resource_id),
            "resource {resource_id} was released without a matching acquire"
        );
        self.released.fetch_add(1, Ordering::SeqCst);
    }

    fn assert_balanced(&self) {
        let live = self
            .live
            .lock()
            .expect("resource tracker mutex should not poison");
        assert!(live.is_empty(), "pooled resources leaked: {live:?}");
        assert_eq!(
            self.acquired.load(Ordering::SeqCst),
            self.released.load(Ordering::SeqCst),
            "resource acquire/release counts must balance"
        );
    }

    fn created_count(&self, factory: &MockFactory) -> usize {
        factory.created.load(Ordering::SeqCst)
    }
}
