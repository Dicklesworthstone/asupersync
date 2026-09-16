//! Entropy source abstraction for deterministic testing.
//!
//! This module provides a capability-friendly entropy interface with
//! deterministic and OS-backed implementations.

use crate::types::TaskId;
use crate::util::DetRng;
use parking_lot::Mutex;
use std::sync::{
    Arc,
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
    fn fork(&self, task_id: TaskId) -> Arc<dyn EntropySource>;

    /// Stable identifier for tracing and diagnostics.
    fn source_id(&self) -> &'static str;
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

    #[inline]
    fn fork(&self, _task_id: TaskId) -> Arc<dyn EntropySource> {
        Arc::new(Self)
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    // Use independent policies so these tests exercise the production guard
    // implementation without changing the global gate used by parallel OS
    // entropy tests elsewhere in the crate.
    #[test]
    fn strict_guards_preserve_isolation_in_every_drop_order() {
        static POLICY: StrictEntropyPolicy = StrictEntropyPolicy::new();
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut guards = [
                Some(StrictEntropyGuard::with_policy(&POLICY)),
                Some(StrictEntropyGuard::with_policy(&POLICY)),
                Some(StrictEntropyGuard::with_policy(&POLICY)),
            ];
            assert!(POLICY.enabled());
            for (dropped, index) in order.into_iter().enumerate() {
                drop(guards[index].take());
                assert_eq!(POLICY.enabled(), dropped < 2, "order={order:?}");
            }
        }
    }

    #[test]
    fn strict_guards_do_not_restore_stale_explicit_policy() {
        static POLICY: StrictEntropyPolicy = StrictEntropyPolicy::new();
        POLICY.enable();
        let guard = StrictEntropyGuard::with_policy(&POLICY);
        POLICY.disable();
        assert!(
            POLICY.enabled(),
            "explicit disable cannot revoke a live guard"
        );
        drop(guard);
        assert!(
            !POLICY.enabled(),
            "the old enabled bit must not be restored"
        );

        let guard = StrictEntropyGuard::with_policy(&POLICY);
        POLICY.enable();
        drop(guard);
        assert!(
            POLICY.enabled(),
            "dropping a guard cannot undo explicit enable"
        );
        POLICY.disable();
        assert!(!POLICY.enabled());
    }

    #[test]
    fn strict_guards_preserve_another_threads_live_scope() {
        static POLICY: StrictEntropyPolicy = StrictEntropyPolicy::new();
        let first = StrictEntropyGuard::with_policy(&POLICY);
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let worker = std::thread::spawn(move || {
            let second = StrictEntropyGuard::with_policy(&POLICY);
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            assert!(POLICY.enabled());
            drop(second);
        });

        entered_rx.recv().unwrap();
        drop(first);
        let protected = POLICY.enabled();
        // Always release and join the worker before asserting, including when
        // testing an implementation with the original out-of-order-drop bug.
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        assert!(protected, "the worker still owned an isolation guard");
        assert!(!POLICY.enabled());
    }

    #[test]
    fn strict_guard_unwind_releases_only_its_own_claim() {
        static POLICY: StrictEntropyPolicy = StrictEntropyPolicy::new();
        let outer = StrictEntropyGuard::with_policy(&POLICY);
        let result = std::panic::catch_unwind(|| {
            let _inner = StrictEntropyGuard::with_policy(&POLICY);
            panic!("exercise strict entropy cleanup");
        });
        assert!(result.is_err());
        assert!(POLICY.enabled());
        drop(outer);
        assert!(!POLICY.enabled());
    }

    #[test]
    fn strict_guard_overflow_fails_closed_without_changing_policy() {
        static POLICY: StrictEntropyPolicy = StrictEntropyPolicy {
            state: AtomicUsize::new(usize::MAX - 1),
        };
        let result = std::panic::catch_unwind(|| StrictEntropyGuard::with_policy(&POLICY));
        assert!(result.is_err());
        assert_eq!(POLICY.state.load(STRICT_ENTROPY_ORDERING), usize::MAX - 1);
        assert!(POLICY.enabled());
    }

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
    fn det_entropy_seed_42_matches_stable_vector() {
        let e = DetEntropy::new(42);

        assert_eq!(e.next_u64(), 0x0000_000A_9551_4AAA);

        let mut bytes = [0u8; 8];
        let e = DetEntropy::new(42);
        e.fill_bytes(&mut bytes);
        assert_eq!(bytes, [0xAA, 0x4A, 0x51, 0x95, 0x0A, 0x00, 0x00, 0x00]);
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
    // BrowserEntropy Tests
    // =========================================================================

    #[test]
    fn browser_entropy_source_id() {
        let entropy = BrowserEntropy;
        assert_eq!(entropy.source_id(), "browser");
    }

    #[test]
    fn browser_entropy_fork_preserves_browser_identity() {
        let entropy = BrowserEntropy;
        let task_id = TaskId::new_for_test(1, 0);
        let forked = entropy.fork(task_id);
        assert_eq!(forked.source_id(), "browser");
    }

    #[test]
    fn browser_entropy_fill_bytes_works() {
        let entropy = BrowserEntropy;
        let mut buf = [0u8; 32];
        entropy.fill_bytes(&mut buf);
        assert!(
            buf.iter().any(|&b| b != 0),
            "browser entropy should produce non-zero bytes"
        );
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

    #[test]
    fn thread_local_entropy_zero_seed_not_correlated() {
        // Regression: global_seed=0 previously produced correlated thread seeds
        // because 0 * constant = 0, making seeds just 0, 1, 2, ...
        let tl = ThreadLocalEntropy::new(0);

        let e0 = tl.for_thread(0);
        let e1 = tl.for_thread(1);
        let e2 = tl.for_thread(2);

        let v0 = e0.next_u64();
        let v1 = e1.next_u64();
        let v2 = e2.next_u64();

        assert_ne!(v0, v1);
        assert_ne!(v1, v2);
        assert_ne!(v0, v2);
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
