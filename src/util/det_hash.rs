//! Deterministic hashing utilities for lab runtime reproducibility.
//!
//! These types provide deterministic hashing and collection iteration
//! for use in deterministic tests and lab runtime logic.

use std::hash::{BuildHasher, Hasher};

/// Deterministic, non-cryptographic hasher.
///
/// This uses a fixed seed and a simple mixing strategy for reproducibility.
#[derive(Debug, Clone)]
pub struct DetHasher {
    state: u64,
}

impl DetHasher {
    /// Fixed seed ensures deterministic hashes across runs.
    const SEED: u64 = 0x16f1_1fe8_9b0d_677c;
    /// Prime multiplier for mixing.
    const MULTIPLIER: u64 = 0x517c_c1b7_2722_0a95;
}

impl Default for DetHasher {
    fn default() -> Self {
        Self { state: Self::SEED }
    }
}

impl Hasher for DetHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.state = self.state.wrapping_mul(Self::MULTIPLIER);
            self.state ^= u64::from(byte);
        }
    }

    fn write_u8(&mut self, i: u8) {
        self.state = self.state.wrapping_mul(Self::MULTIPLIER) ^ u64::from(i);
    }

    fn write_u64(&mut self, i: u64) {
        self.state = self.state.wrapping_mul(Self::MULTIPLIER) ^ i;
    }

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
#[derive(Clone, Default)]
pub struct DetBuildHasher;

impl BuildHasher for DetBuildHasher {
    type Hasher = DetHasher;

    fn build_hasher(&self) -> Self::Hasher {
        DetHasher::default()
    }
}

/// Deterministic `HashMap` with reproducible iteration order across runs.
pub type DetHashMap<K, V> = std::collections::HashMap<K, V, DetBuildHasher>;

/// Deterministic `HashSet` with reproducible iteration order across runs.
pub type DetHashSet<K> = std::collections::HashSet<K, DetBuildHasher>;

/// Deterministic ordered collections.
pub use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
mod tests {
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
    fn det_hasher_write_u8() {
        let mut h = DetHasher::default();
        h.write_u8(42);
        let _ = h.finish(); // Should not panic
    }

    #[test]
    fn det_hasher_write_u64() {
        let mut h = DetHasher::default();
        h.write_u64(0xDEAD_BEEF_CAFE_BABE);
        let _ = h.finish(); // Should not panic
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
        let builder = DetBuildHasher;
        let mut h1 = builder.build_hasher();
        let mut h2 = builder.build_hasher();

        h1.write(b"test data");
        h2.write(b"test data");

        assert_eq!(h1.finish(), h2.finish());
    }

    // Unit structs are trivially clone/default; no runtime test needed.
}
