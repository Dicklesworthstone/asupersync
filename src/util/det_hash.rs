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
