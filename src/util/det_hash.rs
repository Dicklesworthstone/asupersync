//! Deterministic hashing utilities for lab runtime reproducibility.
//!
//! These types provide deterministic hashing and collection iteration
//! for use in deterministic tests and lab runtime logic.
//!
//! # Security boundary (br-asupersync-yrwie0, br-asupersync-g8lqgh)
//!
//! `DetHasher` behavior depends on build configuration:
//! - **Test builds** (with `test-internals` feature): Uses fixed published seed
//!   for deterministic lab runtime and reproducible schedule exploration.
//! - **Production builds** (without `test-internals`): Uses OS-derived random
//!   seed to prevent hash collision DoS attacks.
//!
//! The fixed seed in test builds makes collision attacks trivial - an attacker
//! who reads this source can compute thousands of distinct keys that all hash
//! to the same bucket and weaponize the resulting O(n²) HashMap collisions into
//! CPU-exhaustion DoS. Production builds automatically use random seeding.
//!
//! **Use `DetHashMap` / `DetHashSet` for**:
//!   * Internal-only key spaces (TaskId, RegionId, ModuleId, etc.) where
//!     keys come from monotonic counters or trusted runtime sources.
//!   * Lab-runtime / replay paths where determinism is REQUIRED for
//!     reproducible execution and the keys are not externally supplied.
//!
//! **For attacker-controlled keys, prefer**:
//!   * `ProductionHashMap` / `ProductionHashSet` for explicit random seeding
//!   * `std::collections::HashMap` with its default `RandomState`
//!   * `BTreeMap` / `BTreeSet` for deterministic ordered iteration
//!
//! **Avoid with attacker-controlled keys**:
//!   * HTTP header names, query parameters, cookie names, or any other
//!     value that arrives from a network peer.
//!   * Cache keys derived from user input.
//!   * JSON-object keys parsed from request bodies.

use std::hash::{BuildHasher, Hasher};

/// Deterministic, non-cryptographic hasher.
///
/// This uses either a fixed seed (for lab determinism) or a random seed
/// (for production security) with a simple mixing strategy.
///
/// **WARNING**: see the module-level "Security boundary" docs.
/// Only use the fixed-seed version (`DetHasher::for_lab()`) in lab runtime
/// where determinism is required. For production use with potentially
/// attacker-controlled keys, use `DetHasher::for_production()`.
#[derive(Debug, Clone)]
pub struct DetHasher {
    state: u64,
}

impl DetHasher {
    /// Fixed seed for deterministic lab runtime hashes.
    const LAB_SEED: u64 = 0x16f1_1fe8_9b0d_677c;
    /// Prime multiplier for mixing.
    const MULTIPLIER: u64 = 0x517c_c1b7_2722_0a95;

    /// Creates a hasher with a fixed seed for lab runtime determinism.
    ///
    /// **Security**: Only use this when deterministic hashing is required
    /// and keys are NOT attacker-controlled. The fixed seed makes collision
    /// attacks trivial.
    #[inline]
    #[must_use]
    pub fn for_lab() -> Self {
        Self {
            state: Self::LAB_SEED,
        }
    }

    /// Creates a hasher with a random seed for production security.
    ///
    /// **Security**: Use this for any HashMap/HashSet where keys might be
    /// attacker-controlled (HTTP headers, user input, etc.). The random
    /// seed prevents practical collision attacks.
    #[inline]
    #[must_use]
    pub fn for_production() -> Self {
        use std::collections::hash_map::RandomState;
        use std::hash::Hash;

        // Generate a random seed using the same entropy source as std::HashMap
        let random_state = RandomState::new();
        let mut hasher = random_state.build_hasher();

        // Hash some unique data to get our random seed
        std::ptr::addr_of!(random_state).hash(&mut hasher);
        std::thread::current().id().hash(&mut hasher);

        Self {
            state: hasher.finish(),
        }
    }

    #[inline]
    fn mix_byte(&mut self, byte: u8) {
        self.state = self.state.wrapping_mul(Self::MULTIPLIER);
        self.state ^= u64::from(byte);
    }

    #[inline]
    fn mix_bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.mix_byte(byte);
        }
    }
}

impl Default for DetHasher {
    /// Default hasher selection based on build configuration.
    ///
    /// **Security**: Uses fixed seed only in test builds (test-internals feature).
    /// Production builds default to random seeding for hash collision DoS protection.
    #[inline]
    fn default() -> Self {
        #[cfg(feature = "test-internals")]
        {
            Self::for_lab()
        }
        #[cfg(not(feature = "test-internals"))]
        {
            Self::for_production()
        }
    }
}

impl Hasher for DetHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.mix_bytes(bytes);
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.mix_byte(i);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.mix_bytes(&i.to_le_bytes());
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.mix_bytes(&i.to_le_bytes());
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.mix_bytes(&i.to_le_bytes());
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.mix_bytes(&i.to_le_bytes());
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        // Always cast to u64 for width-independent consistent hashing.
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_i8(&mut self, i: i8) {
        self.write_u8(i.cast_unsigned());
    }

    #[inline]
    fn write_i16(&mut self, i: i16) {
        self.write_u16(i.cast_unsigned());
    }

    #[inline]
    fn write_i32(&mut self, i: i32) {
        self.write_u32(i.cast_unsigned());
    }

    #[inline]
    fn write_i64(&mut self, i: i64) {
        self.write_u64(i.cast_unsigned());
    }

    #[inline]
    fn write_i128(&mut self, i: i128) {
        self.write_u128(i.cast_unsigned());
    }

    #[inline]
    fn write_isize(&mut self, i: isize) {
        self.write_i64(i as i64);
    }

    #[inline]
    fn finish(&self) -> u64 {
        // Final mixing for better distribution.
        let mut h = self.state;
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        h ^= h >> 33;
        h
    }
}

/// Builder for deterministic hashers.
///
/// The seed is captured once when the builder is created and reused for every
/// `build_hasher` call. `HashMap`/`HashSet` require this: inserting, looking
/// up, and removing one key must hash that key identically within one
/// collection. Production mode remains randomized per builder, not per probe.
#[derive(Clone)]
pub struct DetBuildHasher {
    seed: u64,
}

impl Default for DetBuildHasher {
    /// Default hasher builder based on build configuration.
    ///
    /// **Security**: Uses fixed seed only in test builds (test-internals feature).
    /// Production builds default to random seeding for hash collision DoS protection.
    fn default() -> Self {
        #[cfg(feature = "test-internals")]
        {
            Self::for_lab()
        }
        #[cfg(not(feature = "test-internals"))]
        {
            Self::for_production()
        }
    }
}

impl DetBuildHasher {
    /// Creates a builder that produces lab hashers (fixed seed).
    ///
    /// **Security**: Only use for deterministic lab runtime or trusted keys.
    #[inline]
    #[must_use]
    pub fn for_lab() -> Self {
        Self {
            seed: DetHasher::for_lab().state,
        }
    }

    /// Creates a builder that produces production hashers.
    ///
    /// **Security**: Use for any HashMap/HashSet with attacker-controlled keys.
    /// The seed is random per builder and stable across all hashers built from
    /// that builder.
    #[inline]
    #[must_use]
    pub fn for_production() -> Self {
        Self {
            seed: DetHasher::for_production().state,
        }
    }

    /// Creates a builder whose hashing is deterministically derived from an
    /// explicit seed, independent of build features.
    ///
    /// This is the constructor lab-runtime state must use (GH#55): the lab
    /// scheduler's collections are seeded from `LabConfig::seed`, so two runs
    /// with the same lab seed hash — and therefore iterate — identically even
    /// in builds without the `test-internals` feature. Determinism is a
    /// correctness property of the lab runtime, not a diagnostics feature.
    ///
    /// **Security**: Only use for trusted, internal key spaces (TaskId,
    /// RegionId, io tokens, ...). The derivation is public, so collision
    /// attacks are trivial if keys are attacker-controlled.
    #[inline]
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut hasher = DetHasher::for_lab();
        hasher.write_u64(seed);
        Self {
            seed: hasher.finish(),
        }
    }
}

impl BuildHasher for DetBuildHasher {
    type Hasher = DetHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        DetHasher { state: self.seed }
    }
}

/// `HashMap` with configuration-dependent hashing.
///
/// **Security**: Uses fixed seed in test builds, random seed in production.
/// Safe for trusted keys (TaskId, RegionId, etc.) in both configurations.
/// For explicit control over seeding, use `ProductionHashMap` (always random)
/// or call `HashMap::with_hasher(DetBuildHasher::for_lab())` (always fixed).
///
/// Note: iteration order is NOT guaranteed to be reproducible across runs or
/// Rust versions. Use `BTreeMap` if deterministic iteration order is required.
pub type DetHashMap<K, V> = std::collections::HashMap<K, V, DetBuildHasher>;

/// `HashSet` with configuration-dependent hashing.
///
/// **Security**: Uses fixed seed in test builds, random seed in production.
/// Safe for trusted keys (TaskId, RegionId, etc.) in both configurations.
/// For explicit control over seeding, use `ProductionHashSet` (always random)
/// or call `HashSet::with_hasher(DetBuildHasher::for_lab())` (always fixed).
///
/// Note: iteration order is NOT guaranteed to be reproducible across runs or
/// Rust versions. Use `BTreeSet` if deterministic iteration order is required.
pub type DetHashSet<K> = std::collections::HashSet<K, DetBuildHasher>;

/// `HashMap` with production-safe random seeding.
///
/// **Security**: Safe to use with attacker-controlled keys. Uses random
/// seeding to prevent hash collision DoS attacks.
pub type ProductionHashMap<K, V> = std::collections::HashMap<K, V, ProductionBuildHasher>;

/// `HashSet` with production-safe random seeding.
///
/// **Security**: Safe to use with attacker-controlled keys. Uses random
/// seeding to prevent hash collision DoS attacks.
pub type ProductionHashSet<K> = std::collections::HashSet<K, ProductionBuildHasher>;

/// Builder that always produces production-safe hashers with random seeding.
///
/// The random seed is captured **once** when the builder is created and reused
/// for every `build_hasher` call. This is required for `HashMap`/`HashSet`
/// correctness: a given key must hash identically on insert and lookup, so all
/// hashers produced by one builder must share the same seed. (Re-randomizing
/// per `build_hasher` would make every probe hash differently and silently
/// break the map.) Per-process randomization across distinct builders still
/// defeats hash-collision DoS for attacker-controlled keys.
#[derive(Debug, Clone)]
pub struct ProductionBuildHasher {
    seed: u64,
}

impl Default for ProductionBuildHasher {
    #[inline]
    fn default() -> Self {
        Self {
            seed: DetHasher::for_production().state,
        }
    }
}

impl BuildHasher for ProductionBuildHasher {
    type Hasher = DetHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        DetHasher { state: self.seed }
    }
}

/// Deterministic ordered collections.
pub use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
#[path = "det_hash_inline_tests.rs"]
mod tests;
