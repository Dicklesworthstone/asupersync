//! Entropy source abstraction for deterministic testing.
//!
//! This module provides a capability-friendly entropy interface with
//! deterministic and OS-backed implementations.

use crate::types::TaskId;
use crate::util::DetRng;
use std::sync::{Arc, Mutex};

/// Core trait for entropy providers.
pub trait EntropySource: Send + Sync + 'static {
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
        getrandom::getrandom(dest).expect("OS entropy failed");
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
