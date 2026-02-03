//! Entropy source abstraction for deterministic testing.
//!
//! This module provides a capability-friendly entropy interface with
//! deterministic and OS-backed implementations.

use crate::types::TaskId;
use crate::util::DetRng;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

/// Core trait for entropy providers.
pub trait EntropySource: std::fmt::Debug + Send + Sync + 'static {
    /// Fill a buffer with entropy bytes.
    fn fill_bytes(&self, dest: &mut [u8]);

    /// Return the next random `u64`.
    fn next_u64(&self) -> u64;

    /// Fork this entropy source deterministically for a child task.
    fn fork(&self, task_id: TaskId) -> Arc<dyn EntropySource>;

    /// Stable identifier for tracing and diagnostics.
    fn source_id(&self) -> &'static str;
}

/// OS-backed entropy source for production use.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) {
        check_ambient_entropy("os");
        getrandom::fill(dest).expect("OS entropy failed");
    }

    fn next_u64(&self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fork(&self, _task_id: TaskId) -> Arc<dyn EntropySource> {
        Arc::new(Self)
    }

    fn source_id(&self) -> &'static str {
        "os"
    }
}

/// Deterministic entropy source for lab runtime.
#[derive(Debug)]
pub struct DetEntropy {
    inner: Mutex<DetEntropyInner>,
    seed: u64,
}

#[derive(Debug)]
struct DetEntropyInner {
    rng: DetRng,
    fork_counter: u64,
}

impl DetEntropy {
    /// Create a deterministic entropy source from a seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            inner: Mutex::new(DetEntropyInner {
                rng: DetRng::new(seed),
                fork_counter: 0,
            }),
            seed,
        }
    }

    fn with_fork_counter(seed: u64, fork_counter: u64) -> Self {
        Self {
            inner: Mutex::new(DetEntropyInner {
                rng: DetRng::new(seed),
                fork_counter,
            }),
            seed,
        }
    }

    fn task_seed(task_id: TaskId) -> u64 {
        let idx = task_id.arena_index();
        ((u64::from(idx.generation())) << 32) | u64::from(idx.index())
    }

    fn mix_seed(mut seed: u64) -> u64 {
        seed ^= seed >> 30;
        seed = seed.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        seed ^= seed >> 27;
        seed = seed.wrapping_mul(0x94d0_49bb_1331_11eb);
        seed ^= seed >> 31;
        seed
    }
}

impl EntropySource for DetEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) {
        let mut inner = self.inner.lock().expect("det entropy lock poisoned");
        inner.rng.fill_bytes(dest);
    }

    fn next_u64(&self) -> u64 {
        self.inner
            .lock()
            .expect("det entropy lock poisoned")
            .rng
            .next_u64()
    }

    fn fork(&self, task_id: TaskId) -> Arc<dyn EntropySource> {
        let mut inner = self.inner.lock().expect("det entropy lock poisoned");
        let counter = inner.fork_counter;
        inner.fork_counter = inner.fork_counter.wrapping_add(1);
        drop(inner);

        let mut child_seed = self.seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        child_seed = child_seed.wrapping_add(Self::task_seed(task_id));
        child_seed = child_seed.wrapping_add(counter);
        child_seed = Self::mix_seed(child_seed);
        Arc::new(Self::with_fork_counter(child_seed, 0))
    }

    fn source_id(&self) -> &'static str {
        "deterministic"
    }
}

/// Thread-local deterministic entropy sources derived from a global seed.
#[derive(Debug, Clone)]
pub struct ThreadLocalEntropy {
    global_seed: u64,
}

impl ThreadLocalEntropy {
    /// Create a thread-local entropy factory from a global seed.
    #[must_use]
    pub const fn new(global_seed: u64) -> Self {
        Self { global_seed }
    }

    /// Deterministically derive an entropy source for a worker index.
    #[must_use]
    pub fn for_thread(&self, thread_index: usize) -> DetEntropy {
        let seed = self
            .global_seed
            .wrapping_mul(0x517c_c1b7_2722_0a95)
            .wrapping_add(thread_index as u64);
        DetEntropy::new(seed)
    }
}

// ============================================================================
// Strict entropy isolation (lab tooling)
// ============================================================================

static STRICT_ENTROPY: AtomicBool = AtomicBool::new(false);

/// Enable strict entropy isolation globally.
pub fn enable_strict_entropy() {
    STRICT_ENTROPY.store(true, Ordering::SeqCst);
}

/// Disable strict entropy isolation globally.
pub fn disable_strict_entropy() {
    STRICT_ENTROPY.store(false, Ordering::SeqCst);
}

/// Returns true if strict entropy isolation is enabled.
#[must_use]
pub fn strict_entropy_enabled() -> bool {
    STRICT_ENTROPY.load(Ordering::SeqCst)
}

/// Panic if strict entropy isolation is enabled.
pub fn check_ambient_entropy(source: &str) {
    assert!(
        !strict_entropy_enabled(),
        "ambient entropy source \"{source}\" used in strict mode; use Cx::random_* instead"
    );
}

/// RAII guard to enable strict entropy isolation for a scope.
#[derive(Debug)]
pub struct StrictEntropyGuard {
    previous: bool,
}

impl StrictEntropyGuard {
    /// Enables strict entropy isolation until dropped.
    #[must_use]
    pub fn new() -> Self {
        let previous = STRICT_ENTROPY.swap(true, Ordering::SeqCst);
        Self { previous }
    }
}

impl Default for StrictEntropyGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for StrictEntropyGuard {
    fn drop(&mut self) {
        STRICT_ENTROPY.store(self.previous, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // DetEntropy Core Functionality
    // =========================================================================

    #[test]
    fn det_entropy_same_seed_same_sequence() {
        let e1 = DetEntropy::new(42);
        let e2 = DetEntropy::new(42);

        for _ in 0..32 {
            assert_eq!(e1.next_u64(), e2.next_u64());
        }
    }

    #[test]
    fn det_entropy_different_seeds_different_sequences() {
        let e1 = DetEntropy::new(12345);
        let e2 = DetEntropy::new(54321);

        let v1 = e1.next_u64();
        let v2 = e2.next_u64();
        assert_ne!(v1, v2, "Different seeds should produce different values");
    }

    #[test]
    fn det_entropy_fill_bytes_deterministic() {
        let e1 = DetEntropy::new(42);
        let e2 = DetEntropy::new(42);

        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];

        e1.fill_bytes(&mut buf1);
        e2.fill_bytes(&mut buf2);

        assert_eq!(buf1, buf2);
    }

    #[test]
    fn det_entropy_fork_deterministic() {
        let parent1 = DetEntropy::new(99);
        let parent2 = DetEntropy::new(99);
        let task = TaskId::new_for_test(7, 0);

        let child1 = parent1.fork(task);
        let child2 = parent2.fork(task);

        for _ in 0..16 {
            assert_eq!(child1.next_u64(), child2.next_u64());
        }
    }

    #[test]
    fn det_entropy_fork_different_tasks_different_sequences() {
        let parent = DetEntropy::new(42);

        let task1 = TaskId::new_for_test(1, 0);
        let task2 = TaskId::new_for_test(2, 0);

        let child1 = parent.fork(task1);
        let child2 = parent.fork(task2);

        assert_ne!(
            child1.next_u64(),
            child2.next_u64(),
            "Different task IDs should produce different children"
        );
    }

    #[test]
    fn det_entropy_sequential_forks_different() {
        let parent = DetEntropy::new(42);
        let task_id = TaskId::new_for_test(1, 0);

        let child1 = parent.fork(task_id);
        let child2 = parent.fork(task_id);

        assert_ne!(
            child1.next_u64(),
            child2.next_u64(),
            "Sequential forks of same task should differ (fork counter)"
        );
    }

    #[test]
    fn det_entropy_source_id() {
        let e = DetEntropy::new(42);
        assert_eq!(e.source_id(), "deterministic");
    }

    // =========================================================================
    // OsEntropy Tests
    // =========================================================================

    #[test]
    fn os_entropy_produces_different_values() {
        let os = OsEntropy;
        let v1 = os.next_u64();
        let v2 = os.next_u64();

        // Extremely unlikely to be equal
        assert_ne!(v1, v2, "OS entropy should produce different values");
    }

    #[test]
    fn os_entropy_fill_bytes_works() {
        let os = OsEntropy;
        let mut buf = [0u8; 32];
        os.fill_bytes(&mut buf);

        // Check not all zeros (astronomically unlikely with real entropy)
        assert!(
            buf.iter().any(|&b| b != 0),
            "OS entropy should produce non-zero bytes"
        );
    }

    #[test]
    fn os_entropy_source_id() {
        let os = OsEntropy;
        assert_eq!(os.source_id(), "os");
    }

    #[test]
    fn os_entropy_fork_returns_os_entropy() {
        let os = OsEntropy;
        let task_id = TaskId::new_for_test(1, 0);
        let forked = os.fork(task_id);
        assert_eq!(forked.source_id(), "os");
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn det_entropy_zero_seed_works() {
        let e = DetEntropy::new(0);
        let _ = e.next_u64(); // Should not panic
    }

    #[test]
    fn det_entropy_max_seed_works() {
        let e = DetEntropy::new(u64::MAX);
        let _ = e.next_u64(); // Should not panic or overflow
    }

    #[test]
    fn det_entropy_fill_zero_bytes() {
        let e = DetEntropy::new(42);
        let mut buf: [u8; 0] = [];
        e.fill_bytes(&mut buf); // Should not panic
    }

    // =========================================================================
    // ThreadLocalEntropy Tests
    // =========================================================================

    #[test]
    fn thread_local_entropy_deterministic() {
        let tl1 = ThreadLocalEntropy::new(1234);
        let tl2 = ThreadLocalEntropy::new(1234);

        let e1 = tl1.for_thread(3);
        let e2 = tl2.for_thread(3);

        assert_eq!(e1.next_u64(), e2.next_u64());
    }

    #[test]
    fn thread_local_entropy_different_threads() {
        let tl = ThreadLocalEntropy::new(12345);

        let e0 = tl.for_thread(0);
        let e1 = tl.for_thread(1);

        assert_ne!(e0.next_u64(), e1.next_u64());
    }

    // =========================================================================
    // Thread Safety Tests
    // =========================================================================

    #[test]
    fn det_entropy_thread_safe() {
        use std::thread;

        let e = Arc::new(DetEntropy::new(42));
        let mut handles = vec![];

        for _ in 0..4 {
            let entropy = Arc::clone(&e);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    let _ = entropy.next_u64();
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }
    }
}
