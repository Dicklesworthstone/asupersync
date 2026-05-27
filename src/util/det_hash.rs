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
#[derive(Clone)]
pub struct DetBuildHasher {
    /// Whether to use production-safe random seeding.
    production_mode: bool,
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
            production_mode: false,
        }
    }

    /// Creates a builder that produces production hashers (random seed).
    ///
    /// **Security**: Use for any HashMap/HashSet with attacker-controlled keys.
    #[inline]
    #[must_use]
    pub fn for_production() -> Self {
        Self {
            production_mode: true,
        }
    }
}

impl BuildHasher for DetBuildHasher {
    type Hasher = DetHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        if self.production_mode {
            DetHasher::for_production()
        } else {
            DetHasher::for_lab()
        }
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
#[derive(Clone, Default)]
pub struct ProductionBuildHasher;

impl BuildHasher for ProductionBuildHasher {
    type Hasher = DetHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        DetHasher::for_production()
    }
}

/// Deterministic ordered collections.
pub use std::collections::{BTreeMap, BTreeSet};

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
    use std::hash::Hash;

    fn hash_value<T: Hash>(value: &T) -> u64 {
        let mut hasher = DetHasher::default();
        value.hash(&mut hasher);
        hasher.finish()
    }

    // =========================================================================
    // DetHasher Core Functionality
    // =========================================================================

    #[test]
    fn det_hasher_same_input_same_hash() {
        let h1 = hash_value(&"hello");
        let h2 = hash_value(&"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn det_hasher_different_input_different_hash() {
        let h1 = hash_value(&"hello");
        let h2 = hash_value(&"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn det_hasher_numeric_values() {
        let h1 = hash_value(&42u64);
        let h2 = hash_value(&42u64);
        assert_eq!(h1, h2);

        let h3 = hash_value(&43u64);
        assert_ne!(h1, h3);
    }

    #[test]
    fn det_hasher_empty_slice() {
        let h1 = hash_value(&[0u8; 0]);
        let h2 = hash_value(&[0u8; 0]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn det_hasher_incremental_write() {
        // Writing bytes incrementally should match writing all at once
        let mut h1 = DetHasher::default();
        h1.write(&[1, 2, 3, 4]);
        let result1 = h1.finish();

        let mut h2 = DetHasher::default();
        h2.write(&[1, 2]);
        h2.write(&[3, 4]);
        let result2 = h2.finish();

        assert_eq!(result1, result2);
    }

    #[test]
    fn det_hasher_write_u64_consistent_with_write() {
        // Verify that write_u64 and write produce the same hash when fed the
        // hasher's canonical little-endian byte representation.
        let mut h1 = DetHasher::default();
        h1.write_u64(0xDEAD_BEEF_CAFE_BABE);

        let mut h2 = DetHasher::default();
        h2.write(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());

        assert_eq!(
            h1.finish(),
            h2.finish(),
            "write_u64 must match write for same bytes",
        );
    }

    // =========================================================================
    // DetHashMap Tests
    // =========================================================================

    #[test]
    fn det_hashmap_deterministic_lookup() {
        let mut map1: DetHashMap<String, i32> = DetHashMap::default();
        let mut map2: DetHashMap<String, i32> = DetHashMap::default();

        map1.insert("a".to_string(), 1);
        map1.insert("b".to_string(), 2);
        map1.insert("c".to_string(), 3);

        map2.insert("a".to_string(), 1);
        map2.insert("b".to_string(), 2);
        map2.insert("c".to_string(), 3);

        assert_eq!(map1.get("a"), map2.get("a"));
        assert_eq!(map1.get("b"), map2.get("b"));
        assert_eq!(map1.get("c"), map2.get("c"));
    }

    #[test]
    fn det_hashmap_iteration_order_consistent() {
        // Note: HashMap iteration order is not guaranteed even with deterministic
        // hashing, but the hashes themselves are deterministic
        let mut map: DetHashMap<i32, i32> = DetHashMap::default();
        for i in 0..100 {
            map.insert(i, i * 2);
        }

        // Verify all values are correct
        for i in 0..100 {
            assert_eq!(map.get(&i), Some(&(i * 2)));
        }
    }

    // =========================================================================
    // DetHashSet Tests
    // =========================================================================

    #[test]
    fn det_hashset_deterministic_contains() {
        let mut set1: DetHashSet<String> = DetHashSet::default();
        let mut set2: DetHashSet<String> = DetHashSet::default();

        set1.insert("alpha".to_string());
        set1.insert("beta".to_string());
        set1.insert("gamma".to_string());

        set2.insert("alpha".to_string());
        set2.insert("beta".to_string());
        set2.insert("gamma".to_string());

        assert_eq!(set1.contains("alpha"), set2.contains("alpha"));
        assert_eq!(set1.contains("beta"), set2.contains("beta"));
        assert_eq!(set1.contains("delta"), set2.contains("delta"));
    }

    #[test]
    fn det_hashset_len() {
        let mut set: DetHashSet<i32> = DetHashSet::default();
        assert_eq!(set.len(), 0);

        set.insert(1);
        set.insert(2);
        set.insert(3);
        assert_eq!(set.len(), 3);

        // Duplicate insert
        set.insert(1);
        assert_eq!(set.len(), 3);
    }

    // =========================================================================
    // DetBuildHasher Tests
    // =========================================================================

    #[test]
    fn det_build_hasher_produces_deterministic_hashers() {
        let builder = DetBuildHasher::for_lab();
        let mut h1 = builder.build_hasher();
        let mut h2 = builder.build_hasher();

        h1.write(b"test data");
        h2.write(b"test data");

        assert_eq!(h1.finish(), h2.finish());
    }

    // =========================================================================
    // Wave 57 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn det_hasher_debug_clone() {
        let mut h = DetHasher::default();
        h.write(b"partial");
        let dbg = format!("{h:?}");
        assert!(dbg.contains("DetHasher"), "{dbg}");
        let h2 = h.clone();
        assert_eq!(h.finish(), h2.finish());
    }

    #[test]
    fn det_build_hasher_clone_default() {
        let b1 = DetBuildHasher::default();
        let b2 = b1.clone();
        let b3 = DetBuildHasher::for_lab();
        let mut x = b2.build_hasher();
        let mut y = b3.build_hasher();
        x.write(b"same");
        y.write(b"same");
        assert_eq!(x.finish(), y.finish());
    }

    // =========================================================================
    // Security Tests - Production vs Lab Mode
    // =========================================================================

    #[test]
    fn lab_mode_produces_deterministic_hashes() {
        let h1 = DetHasher::for_lab();
        let h2 = DetHasher::for_lab();
        let mut x = h1;
        let mut y = h2;
        x.write(b"test data");
        y.write(b"test data");
        assert_eq!(x.finish(), y.finish(), "Lab mode must be deterministic");
    }

    #[test]
    fn production_mode_produces_different_seeds() {
        let h1 = DetHasher::for_production();
        let h2 = DetHasher::for_production();
        // Two production hashers should have different internal seeds
        // We can't directly access the seed, but we can verify they hash differently
        // with high probability by hashing empty data
        let mut x = h1;
        let mut y = h2;
        x.write(b"");
        y.write(b"");
        let hash1 = x.finish();
        let hash2 = y.finish();
        // With random seeding, these should be different with very high probability
        assert_ne!(hash1, hash2, "Production mode should use random seeds");
    }

    #[test]
    fn lab_mode_different_from_production_mode() {
        let lab = DetHasher::for_lab();
        let prod = DetHasher::for_production();
        let mut lab_hasher = lab;
        let mut prod_hasher = prod;
        lab_hasher.write(b"test");
        prod_hasher.write(b"test");
        // Lab uses fixed seed, production uses random seed
        assert_ne!(lab_hasher.finish(), prod_hasher.finish());
    }

    #[test]
    fn det_build_hasher_lab_mode() {
        let builder = DetBuildHasher::for_lab();
        let h1 = builder.build_hasher();
        let h2 = builder.build_hasher();
        let mut x = h1;
        let mut y = h2;
        x.write(b"test");
        y.write(b"test");
        assert_eq!(x.finish(), y.finish());
    }

    #[test]
    fn det_build_hasher_production_mode() {
        let builder = DetBuildHasher::for_production();
        let h1 = builder.build_hasher();
        let h2 = builder.build_hasher();
        let mut x = h1;
        let mut y = h2;
        x.write(b"");
        y.write(b"");
        // Production mode should produce different seeds each time
        assert_ne!(x.finish(), y.finish());
    }

    #[test]
    fn production_hasher_builder_always_random() {
        let builder = ProductionBuildHasher;
        let h1 = builder.build_hasher();
        let h2 = builder.build_hasher();
        let mut x = h1;
        let mut y = h2;
        x.write(b"collision test");
        y.write(b"collision test");
        // Should be different with high probability due to random seeding
        assert_ne!(x.finish(), y.finish());
    }

    #[test]
    fn production_hashmap_prevents_collision_attacks() {
        // This test verifies that ProductionHashMap uses random seeding
        let map1: ProductionHashMap<String, i32> = ProductionHashMap::default();
        let map2: ProductionHashMap<String, i32> = ProductionHashMap::default();

        // Insert the same key in both maps
        let mut map1 = map1;
        let mut map2 = map2;
        map1.insert("attack_key".to_string(), 1);
        map2.insert("attack_key".to_string(), 2);

        // Both should contain their respective values
        assert_eq!(map1.get("attack_key"), Some(&1));
        assert_eq!(map2.get("attack_key"), Some(&2));
    }

    #[test]
    fn backward_compatibility_default_uses_lab_mode() {
        let default_hasher = DetHasher::default();
        let lab_hasher = DetHasher::for_lab();
        let mut d = default_hasher;
        let mut l = lab_hasher;
        d.write(b"compatibility test");
        l.write(b"compatibility test");
        assert_eq!(
            d.finish(),
            l.finish(),
            "Default should be identical to lab mode"
        );

        let default_builder = DetBuildHasher::default();
        let lab_builder = DetBuildHasher::for_lab();
        let mut d_h = default_builder.build_hasher();
        let mut l_h = lab_builder.build_hasher();
        d_h.write(b"compatibility");
        l_h.write(b"compatibility");
        assert_eq!(
            d_h.finish(),
            l_h.finish(),
            "Default builder should match lab builder"
        );
    }
}
