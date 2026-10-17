//! Entropy source abstraction for deterministic testing.
//!
//! This module provides a capability-friendly entropy interface with
//! deterministic and OS-backed implementations.

use crate::types::TaskId;
use crate::util::DetRng;
use parking_lot::Mutex;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

// Note: Using getrandom for OS entropy (rand::rngs::OsRng not available as dependency)

/// Core trait for entropy providers.
pub trait EntropySource: std::fmt::Debug + Send + Sync + 'static {
    /// Fill a buffer with entropy bytes.
    fn fill_bytes(&self, dest: &mut [u8]);

    /// Return the next random `u64`.
    fn next_u64(&self) -> u64;

    /// Fork this entropy source deterministically for a child task.
    ///
    /// The runtime forks a task's source when the task is created or
    /// admitted, in spawn order and while it holds its internal state lock,
    /// so that the seeds tasks receive do not depend on the schedule. An
    /// implementation must therefore not call back into the runtime (spawn,
    /// block on a runtime-driven future, or take a lock a task may hold).
    /// A panic is contained: the fork is retried on the task's first use of
    /// entropy, where the panic reaches that task.
    fn fork(&self, task_id: TaskId) -> Arc<dyn EntropySource>;

    /// Stable identifier for tracing and diagnostics.
    fn source_id(&self) -> &'static str;
}

/// A deferred entropy fork that delays calling `parent.fork(task)` until first use.
///
/// The runtime forks eagerly, in spawn order. It falls back to a `DeferredFork`
/// only when a user `EntropySource::fork` panicked under its lock, so the retried
/// fork's panic reaches the task instead.
#[derive(Debug)]
pub struct DeferredFork {
    parent: Arc<dyn EntropySource>,
    task: TaskId,
    forked: OnceLock<Arc<dyn EntropySource>>,
}

impl DeferredFork {
    /// Creates a deferred fork that will invoke `parent.fork(task)` lazily on first access.
    #[must_use]
    pub fn new(parent: Arc<dyn EntropySource>, task: TaskId) -> Self {
        Self {
            parent,
            task,
            forked: OnceLock::new(),
        }
    }

    /// Access the underlying forked source, forcing evaluation if not already done.
    #[must_use]
    pub fn forked(&self) -> &Arc<dyn EntropySource> {
        self.forked.get_or_init(|| self.parent.fork(self.task))
    }
}

impl EntropySource for DeferredFork {
    fn fill_bytes(&self, dest: &mut [u8]) {
        self.forked().fill_bytes(dest);
    }

    fn next_u64(&self) -> u64 {
        self.forked().next_u64()
    }

    fn fork(&self, task_id: TaskId) -> Arc<dyn EntropySource> {
        self.forked().fork(task_id)
    }

    fn source_id(&self) -> &'static str {
        self.forked().source_id()
    }
}

/// Forks `parent` for `task` now, so a source whose children depend on fork
/// order (`DetEntropy` counts forks) forks in spawn order, independent of the
/// schedule. Callers hold runtime locks, so a user fork that panics is caught
/// here and retried lazily on first use ([`DeferredFork`]), where the panic
/// reaches the task instead of unwinding through the lock.
pub(crate) fn fork_contained(
    parent: &Arc<dyn EntropySource>,
    task: TaskId,
) -> Arc<dyn EntropySource> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parent.fork(task)))
        .unwrap_or_else(|_| Arc::new(DeferredFork::new(Arc::clone(parent), task)))
}

/// OS-backed entropy source for production use.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    #[inline]
    fn fill_bytes(&self, dest: &mut [u8]) {
        check_ambient_entropy("os");
        getrandom::fill(dest).expect("OS entropy failed");
    }

    #[inline]
    fn next_u64(&self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    // Every fork is the same stateless source, so tasks share one `Arc`
    // instead of allocating one each (twice per spawned task).
    #[inline]
    fn fork(&self, _task_id: TaskId) -> Arc<dyn EntropySource> {
        static SHARED: std::sync::LazyLock<Arc<dyn EntropySource>> =
            std::sync::LazyLock::new(|| Arc::new(OsEntropy));
        Arc::clone(&SHARED)
    }

    #[inline]
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
    #[inline]
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

    #[inline]
    fn task_seed(task_id: TaskId) -> u64 {
        let idx = task_id.arena_index();
        ((u64::from(idx.generation())) << 32) | u64::from(idx.index())
    }

    #[inline]
    pub(crate) fn mix_seed(mut seed: u64) -> u64 {
        seed ^= seed >> 30;
        seed = seed.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        seed ^= seed >> 27;
        seed = seed.wrapping_mul(0x94d0_49bb_1331_11eb);
        seed ^= seed >> 31;
        seed
    }
}

impl EntropySource for DetEntropy {
    #[inline]
    fn fill_bytes(&self, dest: &mut [u8]) {
        let mut inner = self.inner.lock();
        inner.rng.fill_bytes(dest);
    }

    #[inline]
    fn next_u64(&self) -> u64 {
        self.inner.lock().rng.next_u64()
    }

    #[inline]
    fn fork(&self, task_id: TaskId) -> Arc<dyn EntropySource> {
        let mut inner = self.inner.lock();
        let counter = inner.fork_counter;
        inner.fork_counter = inner.fork_counter.wrapping_add(1);
        drop(inner);

        let mut child_seed = self.seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        child_seed = child_seed.wrapping_add(Self::task_seed(task_id));
        child_seed = child_seed.wrapping_add(counter);
        child_seed = Self::mix_seed(child_seed);
        Arc::new(Self::with_fork_counter(child_seed, 0))
    }

    #[inline]
    fn source_id(&self) -> &'static str {
        "deterministic"
    }
}

/// Browser-labeled entropy source for browser-facing capability plumbing.
///
/// `BrowserEntropy` is an honest thin wrapper around the ambient `getrandom`
/// backend with a distinct `source_id()` of `"browser"`. On
/// `wasm32-unknown-unknown`, the configured `getrandom` JS backend resolves to
/// the browser CSPRNG (for example `crypto.getRandomValues()`); on non-browser
/// targets it still provides real entropy while preserving the browser-specific
/// identity used by routing, diagnostics, and capability policy.
#[derive(Debug, Default, Clone, Copy)]
pub struct BrowserEntropy;

impl EntropySource for BrowserEntropy {
    #[inline]
    fn fill_bytes(&self, dest: &mut [u8]) {
        check_ambient_entropy("browser");
        getrandom::fill(dest).expect("browser entropy failed");
    }

    #[inline]
    fn next_u64(&self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    #[inline]
    fn fork(&self, _task_id: TaskId) -> Arc<dyn EntropySource> {
        Arc::new(Self)
    }

    #[inline]
    fn source_id(&self) -> &'static str {
        "browser"
    }
}

/// Thread-local deterministic entropy sources derived from a global seed.
#[derive(Debug, Clone)]
pub struct ThreadLocalEntropy {
    global_seed: u64,
}

impl ThreadLocalEntropy {
    /// Create a thread-local entropy factory from a global seed.
    #[inline]
    #[must_use]
    pub const fn new(global_seed: u64) -> Self {
        Self { global_seed }
    }

    /// Deterministically derive an entropy source for a worker index.
    #[must_use]
    #[inline]
    pub fn for_thread(&self, thread_index: usize) -> DetEntropy {
        let combined = self
            .global_seed
            .wrapping_add(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(thread_index as u64);
        DetEntropy::new(DetEntropy::mix_seed(combined))
    }
}

// ============================================================================
// Strict entropy isolation (lab tooling)
// ============================================================================

static STRICT_ENTROPY: StrictEntropyPolicy = StrictEntropyPolicy::new();

// The strict entropy state is a standalone policy gate. It does not publish
// side data, so atomicity alone is sufficient; no cross-location ordering is
// required.
const STRICT_ENTROPY_ORDERING: Ordering = Ordering::Relaxed;

/// The low bit holds the explicit policy; each live guard owns two units.
/// Keeping both in one atomic makes policy updates and overlapping scopes
/// compose without a stale saved boolean disabling another scope's isolation.
#[derive(Debug)]
struct StrictEntropyPolicy {
    state: AtomicUsize,
}

impl StrictEntropyPolicy {
    const fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
        }
    }

    #[inline]
    fn enable(&self) {
        self.state.fetch_or(1, STRICT_ENTROPY_ORDERING);
    }

    #[inline]
    fn disable(&self) {
        self.state.fetch_and(!1, STRICT_ENTROPY_ORDERING);
    }

    #[inline]
    fn enabled(&self) -> bool {
        self.state.load(STRICT_ENTROPY_ORDERING) != 0
    }
}

/// Enable strict entropy isolation globally.
///
/// This explicit policy remains enabled after existing guards are dropped.
#[inline]
pub fn enable_strict_entropy() {
    STRICT_ENTROPY.enable();
}

/// Disable the explicit global strict entropy policy.
///
/// Live [`StrictEntropyGuard`] scopes continue to enforce isolation until the
/// last guard is dropped; this call cannot disable another scope's protection.
#[inline]
pub fn disable_strict_entropy() {
    STRICT_ENTROPY.disable();
}

/// Returns true if strict entropy isolation is enabled.
#[inline]
#[must_use]
pub fn strict_entropy_enabled() -> bool {
    STRICT_ENTROPY.enabled()
}

/// Panic if strict entropy isolation is enabled.
#[inline]
pub fn check_ambient_entropy(source: &str) {
    assert!(
        !strict_entropy_enabled(),
        "ambient entropy source \"{source}\" used in strict mode; use Cx::random_* instead"
    );
}

/// RAII guard to enable strict entropy isolation for a scope.
///
/// Guards may overlap across threads and be dropped in any order. Isolation
/// stays enabled while any guard is alive, independently of the explicit global
/// policy. Dropping a guard releases only that guard's claim.
#[derive(Debug)]
pub struct StrictEntropyGuard {
    policy: &'static StrictEntropyPolicy,
}

impl StrictEntropyGuard {
    /// Enables strict entropy isolation until dropped.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::with_policy(&STRICT_ENTROPY)
    }

    #[inline]
    fn with_policy(policy: &'static StrictEntropyPolicy) -> Self {
        // Never wrap the last live guard count to zero (which would admit
        // ambient entropy). A failed acquisition leaves the policy unchanged.
        // Spell out the CAS loop to support both the stable lane and nightly,
        // where fetch_update was renamed to try_update.
        let mut state = policy.state.load(STRICT_ENTROPY_ORDERING);
        loop {
            let next = state
                .checked_add(2)
                .expect("strict entropy guard count exhausted");
            match policy.state.compare_exchange_weak(
                state,
                next,
                STRICT_ENTROPY_ORDERING,
                STRICT_ENTROPY_ORDERING,
            ) {
                Ok(_) => break,
                Err(observed) => state = observed,
            }
        }
        Self { policy }
    }
}

impl Default for StrictEntropyGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for StrictEntropyGuard {
    fn drop(&mut self) {
        let previous = self.policy.state.fetch_sub(2, STRICT_ENTROPY_ORDERING);
        debug_assert!(previous >= 2, "strict entropy guard count underflow");
    }
}

// ============================================================================
// Cryptographic salt generation (br-asupersync-is96u6)
// ============================================================================

/// 256-bit cryptographic salt for hash ring security.
///
/// br-asupersync-is96u6: Provides collision-resistant salt generation
/// for hash rings and consistent hash algorithms. 256-bit entropy
/// defeats birthday paradox attacks up to 2^128 complexity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CryptoSalt([u8; 32]);

impl CryptoSalt {
    /// Generate a cryptographically secure 256-bit salt with domain separation.
    ///
    /// Uses OS entropy source with domain separation to prevent cross-system
    /// salt reuse attacks. The domain parameter should be unique per subsystem.
    #[must_use]
    pub fn generate(domain: &str) -> Self {
        check_ambient_entropy("crypto-salt");
        let mut salt_bytes = [0u8; 32];

        // Primary entropy from OS random number generator (same security as rand::rngs::OsRng)
        getrandom::fill(&mut salt_bytes).expect("crypto salt generation failed");

        // Domain separation via HMAC-like construction
        let mut domain_mixed = [0u8; 32];
        getrandom::fill(&mut domain_mixed).expect("crypto salt domain mixing failed");

        // Mix domain into salt to prevent cross-system reuse
        let domain_bytes = domain.as_bytes();
        for (i, &domain_byte) in domain_bytes.iter().enumerate() {
            if i < 32 {
                salt_bytes[i] ^= domain_byte;
                domain_mixed[i] ^= domain_byte.wrapping_mul(0x9e);
            }
        }

        // Final mixing to ensure uniform distribution
        for i in 0..32 {
            salt_bytes[i] ^= domain_mixed[i];
        }

        Self(salt_bytes)
    }

    /// Generate a deterministic salt for testing from a seed and domain.
    ///
    /// Only for use in tests and lab runtime where deterministic behavior
    /// is required. Production code MUST use `generate()`.
    #[must_use]
    pub fn for_test(seed: u64, domain: &str) -> Self {
        let mut salt_bytes = [0u8; 32];

        // Place seed as first 8 bytes for backward compatibility
        salt_bytes[0..8].copy_from_slice(&seed.to_le_bytes());

        // Fill remaining bytes with deterministic but well-mixed data
        let mut state = seed;
        for chunk in salt_bytes[8..].chunks_exact_mut(8) {
            state = state
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(0x243f_6a88_85a3_08d3);
            chunk.copy_from_slice(&state.to_le_bytes());
        }

        // Domain separation on non-seed bytes to preserve seed recovery
        let domain_bytes = domain.as_bytes();
        for (i, &domain_byte) in domain_bytes.iter().enumerate() {
            // Skip first 8 bytes to preserve seed value for as_u64()
            if (8..32).contains(&i) {
                salt_bytes[i] ^= domain_byte;
            }
        }

        Self(salt_bytes)
    }

    /// Extract a 64-bit value from the salt for compatibility with existing hash functions.
    ///
    /// Uses the first 8 bytes of the salt. For new code, prefer using the full
    /// 256-bit salt through `as_bytes()`.
    #[must_use]
    pub fn as_u64(&self) -> u64 {
        u64::from_le_bytes([
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
        ])
    }

    /// Returns the full 256-bit salt as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Extract a salt subset for domain-specific use.
    ///
    /// Provides domain-separated salt derivation from the master salt.
    /// Each domain gets a cryptographically independent 64-bit value.
    #[must_use]
    pub fn derive_u64(&self, domain_suffix: &str) -> u64 {
        use crate::util::det_hash::DetHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DetHasher::for_production();
        self.0.hash(&mut hasher);
        "crypto-salt-derive".hash(&mut hasher);
        domain_suffix.hash(&mut hasher);
        hasher.finish()
    }
}

impl Default for CryptoSalt {
    /// Generate a new crypto salt with default domain.
    ///
    /// Uses "default" as the domain. Prefer `generate(domain)` with
    /// a specific domain for better security isolation.
    fn default() -> Self {
        Self::generate("default")
    }
}

#[cfg(test)]
#[path = "entropy_inline_tests.rs"]
mod tests;
