#![allow(missing_docs)]
#![allow(clippy::pedantic, clippy::nursery)]
//! Live-allocator canary for the byte-bounded blocking pool.
//!
//! A `BoundedBytes` pool reserves the storage of a queued closure (and what its submitter declared) when it admits
//! the job. That reservation may be returned only AFTER the heap allocation holding the closure has been freed: if
//! it went back while the allocation still existed, a new admission could overlap the old allocation and the limit
//! would not bound what is alive.
//!
//! These tests do not trust field order or call order. They install a counting allocator that watches one exact
//! allocation size (the size of the closure under test, which no other allocation in the process is expected to
//! share) and read its live count at the instant the reservation is observed to have gone back:
//!
//! * a parked submission's waker is woken by the release, so the waker reads the live count at that exact moment;
//! * for a cancelled job a worker retires, a sampler thread reads the reservation and then the live count;
//! * two toy shapes with the same measurement show that it tells a reservation released inside the closure's
//!   allocation (the shape this pool must not have) from one released after it (the shape it has).

use asupersync::runtime::{
    BlockingAdmissionPolicy, BlockingPool, BlockingPoolOptions, BlockingQueuePolicy,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(10);

/// Bytes of array the watched closures capture inline, by value: they make the closure, and so its box, large and
/// of a size nothing else in the process allocates.
const BULK: usize = 6_000;

// ---------------------------------------------------------------------------------------------- counting allocator

/// Size of the one allocation the running scenario watches; 0 watches nothing.
static WATCHED: AtomicUsize = AtomicUsize::new(0);
/// Allocations of exactly the watched size that are live now.
static LIVE: AtomicIsize = AtomicIsize::new(0);

struct Tracker;

// SAFETY: this impl is the only unsafe item in the file, so the `allow` is scoped to it alone. Every method forwards
// its own arguments to `System`, so the `GlobalAlloc` contract (a valid layout, and `dealloc` only of a pointer that
// `alloc` returned for the same layout) is exactly the caller's. The bookkeeping is two atomics read and updated
// around the forwarded call, and nothing here allocates, so the allocator cannot re-enter itself.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Tracker {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let watched = WATCHED.load(Ordering::SeqCst);
        if watched != 0 && layout.size() == watched {
            LIVE.fetch_add(1, Ordering::SeqCst);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        let watched = WATCHED.load(Ordering::SeqCst);
        if watched != 0 && layout.size() == watched {
            LIVE.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

#[global_allocator]
static GLOBAL: Tracker = Tracker;

/// The counters are process-wide, so the scenarios run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn start_watching(size: usize) {
    LIVE.store(0, Ordering::SeqCst);
    WATCHED.store(size, Ordering::SeqCst);
}

fn stop_watching() {
    WATCHED.store(0, Ordering::SeqCst);
}

// -------------------------------------------------------------------------------------------------------- fixtures

fn byte_pool(max_queued: usize, max_live_bytes: usize) -> BlockingPool {
    BlockingPool::with_config_and_policies(
        1,
        1,
        BlockingPoolOptions::default(),
        BlockingQueuePolicy::Fifo,
        BlockingAdmissionPolicy::BoundedBytes {
            max_queued: NonZeroUsize::new(max_queued).unwrap(),
            max_live_bytes: NonZeroUsize::new(max_live_bytes).unwrap(),
        },
    )
}

/// A closure that captures `BULK` bytes inline. When it runs it reports the live count of watched allocations (the
/// tracker must see the closure's own box) and then waits for the gate.
fn bulk_job(
    entered: mpsc::Sender<isize>,
    gate: mpsc::Receiver<()>,
    panics: bool,
) -> impl FnOnce() + Send + 'static {
    let bulk = [3_u8; BULK];
    move || {
        let _inline = &bulk;
        entered.send(LIVE.load(Ordering::SeqCst)).unwrap();
        gate.recv_timeout(WAIT).unwrap();
        if panics {
            panic!("the watched job panics on purpose");
        }
    }
}

/// Woken when a reservation goes back. Records what the pool and the allocator say at that instant.
struct ReleaseProbe {
    pool: asupersync::runtime::BlockingPoolHandle,
    events: Mutex<Vec<(usize, isize)>>,
}

impl ReleaseProbe {
    fn events(&self) -> Vec<(usize, isize)> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Wake for ReleaseProbe {
    fn wake(self: Arc<Self>) {
        let charged = self.pool.charged_bytes();
        let live = LIVE.load(Ordering::SeqCst);
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((charged, live));
    }
}

// ------------------------------------------------------------------------------------------------ the real pool

fn release_follows_free_when_the_job_runs(panics: bool) {
    let _serial = serial();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (open_tx, gate_rx) = mpsc::channel();
    let job = bulk_job(entered_tx, gate_rx, panics);
    let size = std::mem::size_of_val(&job);
    assert!(size >= BULK);
    // The limit holds exactly one such closure.
    let pool = byte_pool(4, size);
    start_watching(size);

    let first = pool.try_spawn_charged(job, 0).unwrap();
    // The job runs out of its box: the tracker sees exactly that one allocation, so the canary is not blind.
    assert_eq!(entered_rx.recv_timeout(WAIT).unwrap(), 1);
    assert_eq!(pool.charged_storage_bytes(), size);
    assert_eq!(pool.charged_declared_bytes(), 0);

    // An identical job does not fit beside it. It parks, and the release of the first job's bytes wakes it.
    let (entered2_tx, entered2_rx) = mpsc::channel();
    let (open2_tx, gate2_rx) = mpsc::channel();
    let mut second = pool.submit_charged(bulk_job(entered2_tx, gate2_rx, false), 0);
    let probe = Arc::new(ReleaseProbe {
        pool: pool.handle(),
        events: Mutex::new(Vec::new()),
    });
    let waker = Waker::from(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);
    assert!(Pin::new(&mut second).poll(&mut context).is_pending());
    assert!(probe.events().is_empty());

    open_tx.send(()).unwrap();
    assert!(first.wait_timeout(WAIT));
    let events = probe.events();
    assert_eq!(
        events.len(),
        1,
        "one release wakes the parked job once: {events:?}"
    );
    let (charged, live) = events[0];
    assert_eq!(charged, 0, "the wake reports the bytes already returned");
    assert_eq!(
        live, 0,
        "the reservation went back while the closure's allocation was still live"
    );

    // The permitted counterpart: the returned bytes admit the parked job, and its own box is a new allocation.
    let accepted = match Pin::new(&mut second).poll(&mut context) {
        Poll::Ready(Ok(handle)) => handle,
        _ => panic!("the returned bytes must admit the parked job"),
    };
    assert_eq!(entered2_rx.recv_timeout(WAIT).unwrap(), 1);
    open2_tx.send(()).unwrap();
    assert!(accepted.wait_timeout(WAIT));
    assert!(pool.shutdown_and_wait(WAIT));
    assert_eq!(pool.charged_bytes(), 0);
    assert_eq!(LIVE.load(Ordering::SeqCst), 0);
    stop_watching();
}

#[test]
fn the_reservation_follows_the_free_when_the_job_runs() {
    release_follows_free_when_the_job_runs(false);
}

#[test]
fn the_reservation_follows_the_free_when_the_job_panics() {
    release_follows_free_when_the_job_runs(true);
}

#[test]
fn the_reservation_follows_the_free_when_a_worker_skips_a_cancelled_job() {
    let _serial = serial();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (open_tx, gate_rx) = mpsc::channel::<()>();
    let blocker = move || {
        entered_tx.send(()).unwrap();
        gate_rx.recv_timeout(WAIT).unwrap();
    };
    let blocker_storage = std::mem::size_of_val(&blocker);
    // The big job never runs: it is cancelled while it waits behind the blocker.
    let (never_tx, _never_rx) = mpsc::channel();
    let (_never_gate, never_gate_rx) = mpsc::channel();
    let job = bulk_job(never_tx, never_gate_rx, false);
    let size = std::mem::size_of_val(&job);
    let pool = byte_pool(4, size + blocker_storage);
    start_watching(size);

    let running = pool.try_spawn_charged(blocker, 0).unwrap();
    entered_rx.recv_timeout(WAIT).unwrap();
    let queued = pool.try_spawn_charged(job, 0).unwrap();
    assert_eq!(
        LIVE.load(Ordering::SeqCst),
        1,
        "the queued closure's box is live"
    );
    assert_eq!(pool.charged_bytes(), size + blocker_storage);
    queued.cancel();
    // Cancelling returns nothing and frees nothing: the closure is still queued.
    assert_eq!(pool.charged_bytes(), size + blocker_storage);
    assert_eq!(LIVE.load(Ordering::SeqCst), 1);

    let stop = Arc::new(AtomicBool::new(false));
    let returned = Arc::new(AtomicUsize::new(0));
    let violations = Arc::new(AtomicUsize::new(0));
    let sampler = {
        let (stop, returned, violations) = (
            Arc::clone(&stop),
            Arc::clone(&returned),
            Arc::clone(&violations),
        );
        let handle = pool.handle();
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let charged = handle.charged_bytes();
                let live = LIVE.load(Ordering::SeqCst);
                // Fewer bytes than the big job alone reserved means its reservation has gone back.
                if charged < size {
                    returned.fetch_add(1, Ordering::SeqCst);
                    if live != 0 {
                        violations.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        })
    };
    open_tx.send(()).unwrap();
    assert!(running.wait_timeout(WAIT));
    assert!(queued.wait_timeout(WAIT));
    std::thread::sleep(Duration::from_millis(50));
    stop.store(true, Ordering::SeqCst);
    sampler.join().unwrap();

    assert!(
        returned.load(Ordering::SeqCst) > 0,
        "the sampler must have observed the returned reservation"
    );
    assert_eq!(
        violations.load(Ordering::SeqCst),
        0,
        "a sample saw the reservation returned while the closure's allocation was live"
    );
    assert!(pool.shutdown_and_wait(WAIT));
    assert_eq!(pool.charged_bytes(), 0);
    assert_eq!(LIVE.load(Ordering::SeqCst), 0);
    stop_watching();
}

// ------------------------------------------------------------------------------------- the canary tells the shapes apart

/// Records the live count of watched allocations at the instant it is dropped.
struct Release {
    seen: Arc<Mutex<Vec<isize>>>,
}

impl Drop for Release {
    fn drop(&mut self) {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(LIVE.load(Ordering::SeqCst));
    }
}

/// The two relevant fields of the pool's queued task, in the same order: the boxed closure, then its reservation.
struct Task {
    _work: Box<dyn FnOnce() + Send + 'static>,
    _release: Release,
}

#[test]
fn the_canary_flags_a_release_inside_the_closure_allocation_and_passes_one_after_it() {
    let _serial = serial();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let observed = || seen.lock().unwrap_or_else(PoisonError::into_inner).clone();

    // Planted shape: the guard lives inside the closure and drops at the end of its body, while the box that holds
    // the closure still exists. This is what a wrapper around the work would do, and it must be detected.
    let release = Release {
        seen: Arc::clone(&seen),
    };
    let bulk = [5_u8; BULK];
    let inside = move || {
        let _guard = release;
        let _inline = &bulk;
    };
    start_watching(std::mem::size_of_val(&inside));
    let boxed: Box<dyn FnOnce() + Send + 'static> = Box::new(inside);
    assert_eq!(LIVE.load(Ordering::SeqCst), 1);
    boxed();
    assert_eq!(LIVE.load(Ordering::SeqCst), 0);
    assert_eq!(
        observed(),
        vec![1],
        "the planted shape releases while the box is live"
    );

    // The pool's shape, called: the reservation sits beside the box and is dropped after the call consumed it.
    let bulk = [6_u8; BULK];
    let work = move || {
        let _inline = &bulk;
    };
    start_watching(std::mem::size_of_val(&work));
    let boxed: Box<dyn FnOnce() + Send + 'static> = Box::new(work);
    let release = Release {
        seen: Arc::clone(&seen),
    };
    assert_eq!(LIVE.load(Ordering::SeqCst), 1);
    boxed();
    drop(release);
    assert_eq!(
        observed(),
        vec![1, 0],
        "a release after the call sees the box freed"
    );

    // The pool's shape, never called (a cancelled or stranded job): the task drops its fields in declaration order.
    let bulk = [7_u8; BULK];
    let unrun = move || {
        let _inline = &bulk;
    };
    start_watching(std::mem::size_of_val(&unrun));
    let task = Task {
        _work: Box::new(unrun),
        _release: Release {
            seen: Arc::clone(&seen),
        },
    };
    assert_eq!(LIVE.load(Ordering::SeqCst), 1);
    drop(task);
    assert_eq!(LIVE.load(Ordering::SeqCst), 0);
    assert_eq!(
        observed(),
        vec![1, 0, 0],
        "an unrun task frees its box before its reservation drops"
    );
    stop_watching();
}
